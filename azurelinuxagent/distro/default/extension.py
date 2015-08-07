# Windows Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.4+ and Openssl 1.0+
#
import os
import zipfile
import time
import json
import subprocess
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.protocol as prot
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import ExtensionError
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.restutil as restutil
import azurelinuxagent.utils.shellutil as shellutil

VALID_EXTENSION_STATUS = ['transitioning', 'error', 'success', 'warning']

def validate_has_key(obj, key, fullname):
    if key not in obj:
        raise ExtensionError("Missing: {0}".format(fullname))

def validate_in_range(val, valid_range, name):
    if val not in valid_range:
        raise ExtensionError("Invalid {0}: {1}".format(name, val))

def try_get(dictionary, key, default=None):
    try:
        return dictionary[key]
    except KeyError:
        return default

def extension_sub_status_to_v2(substatus):
    #Check extension sub status format
    validate_has_key(substatus, 'name', 'substatus/name')
    validate_has_key(substatus, 'status', 'substatus/status')
    validate_has_key(substatus, 'code', 'substatus/code')
    validate_has_key(substatus, 'formattedMessage', 'substatus/formattedMessage')
    validate_has_key(substatus['formattedMessage'], 'lang',
                     'substatus/formattedMessage/lang')
    validate_has_key(substatus['formattedMessage'], 'message',
                     'substatus/formattedMessage/message')

    validate_in_range(substatus['status'], VALID_EXTENSION_STATUS,
                      'substatus/status')
    status = prot.ExtensionSubStatus()
    status.name = try_get(substatus, 'name')
    status.status = try_get(substatus, 'status')
    status.code = try_get(substatus, 'code')
    status.message = try_get(substatus['formattedMessage'], 'message')
    return status

def ext_status_to_v2(ext_status, seq_no):
    #Check extension status format
    validate_has_key(ext_status, 'status', 'status')
    validate_has_key(ext_status['status'], 'status', 'status/status')
    validate_has_key(ext_status['status'], 'operation', 'status/operation')
    validate_has_key(ext_status['status'], 'code', 'status/code')
    validate_has_key(ext_status['status'], 'name', 'status/name')
    validate_has_key(ext_status['status'], 'formattedMessage',
                     'status/formattedMessage')
    validate_has_key(ext_status['status']['formattedMessage'], 'lang',
                     'status/formattedMessage/lang')
    validate_has_key(ext_status['status']['formattedMessage'], 'message',
                     'status/formattedMessage/message')

    validate_in_range(ext_status['status']['status'], VALID_EXTENSION_STATUS,
                      'status/status')

    status = prot.ExtensionStatus()
    status.name = try_get(ext_status['status'], 'name')
    status.configurationAppliedTime = try_get(ext_status['status'],
                                              'configurationAppliedTime')
    status.operation = try_get(ext_status['status'], 'operation')
    status.status = try_get(ext_status['status'], 'status')
    status.code = try_get(ext_status['status'], 'code')
    status.message = try_get(ext_status['status']['formattedMessage'], 'message')
    status.sequenceNumber = seq_no

    substatus_list = try_get(ext_status['status'], 'substatus', [])
    for substatus in substatus_list:
        status.substatusList.extend(extension_sub_status_to_v2(substatus))
    return status

class ExtensionsHandler(object):

    def process(self):
        protocol = prot.FACTORY.get_default_protocol()
        ext_list = protocol.get_extensions()

        h_status_list = []
        for extension in ext_list.extensions:
            #TODO handle extension in parallel
            pkg_list = protocol.get_extension_pkgs(extension)
            h_status = self.process_extension(extension, pkg_list)
            h_status_list.append(h_status)

        return h_status_list

    def process_extension(self, extension, pkg_list):
        installed_version = get_installed_version(extension.name)
        if installed_version is not None:
            ext = ExtensionInstance(extension, pkg_list,
                                    installed_version, installed=True)
        else:
            ext = ExtensionInstance(extension, pkg_list,
                                    extension.properties.version)
        try:
            ext.init_logger()
            ext.handle()
            status = ext.collect_handler_status()
        except ExtensionError as e:
            logger.error("Failed to handle extension: {0}-{1}\n {2}",
                         ext.get_name(), ext.get_version(), e)
            add_event(name=ext.get_name(), is_success=False,
                              op=ext.get_curr_op(), message = text(e))
            ext_status = prot.ExtensionStatus(status='error', code='-1',
                                             operation = ext.get_curr_op(),
                                             message = text(e),
                                             seq_no = ext.get_seq_no())
            status = ext.create_handler_status(ext_status)
            status.status = "Ready"
        return status

def parse_extension_dirname(dirname):
    """
    Parse installed extension dir name. Sample: ExtensionName-Version/
    """
    seprator = dirname.rfind('-')
    if seprator < 0:
        raise ExtensionError("Invalid extenation dir name")
    return dirname[0:seprator], dirname[seprator + 1:]

def get_installed_version(target_name):
    """
    Return the highest version instance with the same name
    """
    installed_version = None
    lib_dir = OSUTIL.get_lib_dir()
    for dir_name in os.listdir(lib_dir):
        path = os.path.join(lib_dir, dir_name)
        if os.path.isdir(path) and dir_name.startswith(target_name):
            name, version = parse_extension_dirname(dir_name)
            #Here we need to ensure names are exactly the same.
            if name == target_name:
                if installed_version is None or installed_version < version:
                    installed_version = version
    return installed_version

class ExtensionInstance(object):
    def __init__(self, extension, pkg_list, curr_version, installed=False):
        self.extension = extension
        self.pkg_list = pkg_list
        self.curr_version = curr_version
        self.lib_dir = OSUTIL.get_lib_dir()
        self.installed = installed
        self.settings = None

        #Extension will have no more than 1 settings instance
        if len(extension.properties.extensions) > 0:
            self.settings = extension.properties.extensions[0]
        self.enabled = False
        self.curr_op = None

        prefix = "[{0}]".format(self.get_full_name())
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)

    def init_logger(self):
        #Init logger appender for extension
        fileutil.mkdir(self.get_log_dir(), mode=0o700)
        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                      logger.LogLevel.INFO, log_file)

    def handle(self):
        self.logger.info("Process extension settings:")
        self.logger.info("  Name: {0}", self.get_name())
        self.logger.info("  Version: {0}", self.get_version())

        if self.installed:
            self.logger.info("Installed version:{0}", self.curr_version)
            h_status = self.get_handler_status()
            self.enabled = (h_status == "Ready")

        state = self.get_state()
        if state == 'enabled':
            self.handle_enable()
        elif state == 'disabled':
            self.handle_disable()
        elif state == 'uninstall':
            self.handle_disable()
            self.handle_uninstall()
        else:
            raise ExtensionError("Unknown extension state:{0}".format(state))

    def handle_enable(self):
        target_version = self.get_target_version()
        if self.installed:
            if target_version > self.curr_version:
                self.upgrade(target_version)
            elif target_version == self.curr_version:
                self.enable()
            else:
                raise ExtensionError("A newer version has already been installed")
        else:
            if target_version > self.get_version():
                #This will happen when auto upgrade policy is enabled
                self.logger.info("Auto upgrade to new version:{0}",
                                 target_version)
                self.curr_version = target_version
            self.download()
            self.init_dir()
            self.install()
            self.enable()

    def handle_disable(self):
        if not self.installed or not self.enabled:
            return
        self.disable()

    def handle_uninstall(self):
        if not self.installed:
            return
        self.uninstall()

    def upgrade(self, target_version):
        self.logger.info("Upgrade from: {0} to {1}", self.curr_version,
                         target_version)
        self.curr_op=WALAEventOperation.Upgrade
        old = self
        new = ExtensionInstance(self.extension, self.pkg_list, target_version)
        self.logger.info("Download new extension package")
        new.init_logger()
        new.download()
        self.logger.info("Initialize new extension directory")
        new.init_dir()

        old.disable()
        self.logger.info("Update new extension")
        new.update()
        old.uninstall()
        man = new.load_manifest()
        if man.is_update_with_install():
            self.logger.info("Install new extension")
            new.install()
        self.logger.info("Enable new extension")
        new.enable()
        add_event(name=self.get_name(), is_success=True,
                  op=self.curr_op, message="")

    def download(self):
        self.logger.info("Download extension package")
        self.curr_op=WALAEventOperation.Download
        uris = self.get_package_uris()
        package = None
        for uri in uris:
            try:
                resp = restutil.http_get(uri.uri, chk_proxy=True)
                package = resp.read()
                break
            except restutil.HttpError as e:
                self.logger.warn("Failed download extension from: {0}", uri.uri)

        if package is None:
            raise ExtensionError("Download extension failed")

        self.logger.info("Unpack extension package")
        pkg_file = os.path.join(self.lib_dir, os.path.basename(uri.uri) + ".zip")
        fileutil.write_file(pkg_file, bytearray(package), asbin=True)
        zipfile.ZipFile(pkg_file).extractall(self.get_base_dir())
        chmod = "find {0} -type f | xargs chmod u+x".format(self.get_base_dir())
        shellutil.run(chmod)
        add_event(name=self.get_name(), is_success=True,
                  op=self.curr_op, message="")

    def init_dir(self):
        self.logger.info("Initialize extension directory")
        #Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(),
                                         'HandlerManifest.json')
        man = fileutil.read_file(man_file, remove_bom=True)
        fileutil.write_file(self.get_manifest_file(), man)

        #Create status and config dir
        status_dir = self.get_status_dir()
        fileutil.mkdir(status_dir, mode=0o700)
        conf_dir = self.get_conf_dir()
        fileutil.mkdir(conf_dir, mode=0o700)

        #Init handler state to uninstall
        self.set_handler_status("NotReady")

        #Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self):
        self.logger.info("Enable extension.")
        self.curr_op=WALAEventOperation.Enable
        man = self.load_manifest()
        self.launch_command(man.get_enable_command())
        self.set_handler_status("Ready")
        add_event(name=self.get_name(), is_success=True,
                          op=self.curr_op, message="")

    def disable(self):
        self.logger.info("Disable extension.")
        self.curr_op=WALAEventOperation.Disable
        man = self.load_manifest()
        self.launch_command(man.get_disable_command(), timeout=900)
        self.set_handler_status("Ready")
        add_event(name=self.get_name(), is_success=True,
                          op=self.curr_op, message="")

    def install(self):
        self.logger.info("Install extension.")
        self.curr_op=WALAEventOperation.Install
        man = self.load_manifest()
        self.set_handler_status("Installing")
        self.launch_command(man.get_install_command(), timeout=900)
        self.set_handler_status("Ready")
        add_event(name=self.get_name(), is_success=True,
                          op=self.curr_op, message="")

    def uninstall(self):
        self.logger.info("Uninstall extension.")
        self.curr_op=WALAEventOperation.UnInstall
        man = self.load_manifest()
        self.launch_command(man.get_uninstall_command())
        self.set_handler_status("NotReady")
        add_event(name=self.get_name(), is_success=True,
                          op=self.curr_op, message="")

    def update(self):
        self.logger.info("Update extension.")
        self.curr_op=WALAEventOperation.Update
        man = self.load_manifest()
        self.launch_command(man.get_update_command(), timeout=900)
        add_event(name=self.get_name(), is_success=True,
                          op=self.curr_op, message="")

    def create_handler_status(self, ext_status, heartbeat=None):
        status = prot.ExtensionHandlerStatus()
        status.handlerName = self.get_name()
        status.handlerVersion = self.get_version()
        status.status = self.get_handler_status()
        status.extensionStatusList.append(ext_status)
        return status

    def collect_handler_status(self):
        man = self.load_manifest()
        heartbeat=None
        if man.is_report_heartbeat():
            heartbeat = self.collect_heartbeat()
        ext_status = self.collect_extension_status()
        status= self.create_handler_status(ext_status, heartbeat)
        status.status = self.get_handler_status()
        if heartbeat is not None:
            status.status = heartbeat['status']
        status.extensionStatusList.append(ext_status)
        return status

    def collect_extension_status(self):
        ext_status_file = self.get_status_file()
        try:
            ext_status_str = fileutil.read_file(ext_status_file)
            ext_status = json.loads(ext_status_str)
        except IOError as e:
            raise ExtensionError("Failed to get status file: {0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed status file: {0}".format(e))
        return ext_status_to_v2(ext_status[0],
                                      self.settings.sequenceNumber)

    def get_handler_status(self):
        h_status = "uninstalled"
        h_status_file = self.get_handler_state_file()
        try:
            h_status = fileutil.read_file(h_status_file)
            return h_status
        except IOError as e:
            raise ExtensionError("Failed to get handler status: {0}".format(e))

    def set_handler_status(self, status):
        h_status_file = self.get_handler_state_file()
        try:
            fileutil.write_file(h_status_file, status)
        except IOError as e:
            raise ExtensionError("Failed to set handler status: {0}".format(e))

    def collect_heartbeat(self):
        self.logger.info("Collect heart beat")
        heartbeat_file = os.path.join(OSUTIL.get_lib_dir(),
                                      self.get_heartbeat_file())
        if not os.path.isfile(heartbeat_file):
            raise ExtensionError("Failed to get heart beat file")
        if not self.is_responsive(heartbeat_file):
            return {
                    "status": "Unresponsive",
                    "code": -1,
                    "message": "Extension heartbeat is not responsive"
            }
        try:
            heartbeat_json = fileutil.read_file(heartbeat_file)
            heartbeat = json.loads(heartbeat_json)[0]['heartbeat']
        except IOError as e:
            raise ExtensionError("Failed to get heartbeat file:{0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed heartbeat file: {0}".format(e))
        return heartbeat

    def is_responsive(self, heartbeat_file):
        last_update=int(time.time()-os.stat(heartbeat_file).st_mtime)
        return  last_update > 600    # not updated for more than 10 min

    def launch_command(self, cmd, timeout=300):
        self.logger.info("Launch command:{0}", cmd)
        base_dir = self.get_base_dir()
        self.update_settings()
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(base_dir + "/" + cmd, shell=True,
                                     cwd=base_dir, stdout=devnull)
        except Exception as e:
            #TODO do not catch all exception
            raise ExtensionError("Failed to launch: {0}, {1}".format(cmd, e))

        retry = timeout / 5
        while retry > 0 and child.poll == None:
            time.sleep(5)
            retry -= 1
        if retry == 0:
            os.kill(child.pid, 9)
            raise ExtensionError("Timeout({0}): {1}".format(timeout, cmd))

        ret = child.wait()
        if ret == None or ret != 0:
            raise ExtensionError("Non-zero exit code: {0}, {1}".format(ret, cmd))

    def load_manifest(self):
        man_file = self.get_manifest_file()
        try:
            data = json.loads(fileutil.read_file(man_file))
        except IOError as e:
            raise ExtensionError('Failed to load manifest file.')
        except ValueError as e:
            raise ExtensionError('Malformed manifest file.')

        return HandlerManifest(data[0])


    def update_settings(self):
        if self.settings is None:
            self.logger.verbose("Extension has no settings")
            return

        settings = {
            'publicSettings': self.settings.publicSettings,
            'protectedSettings': self.settings.privateSettings,
            'protectedSettingsCertThumbprint': self.settings.certificateThumbprint
        }
        ext_settings = {
            "runtimeSettings":[{
                "handlerSettings": settings
            }]
        }
        fileutil.write_file(self.get_settings_file(), json.dumps(ext_settings))

        latest = os.path.join(self.get_conf_dir(), "latest")
        fileutil.write_file(latest, self.settings.sequenceNumber)

    def create_handler_env(self):
        env = [{
            "name": self.get_name(),
            "version" : self.get_version(),
            "handlerEnvironment" : {
                "logFolder" : self.get_log_dir(),
                "configFolder" : self.get_conf_dir(),
                "statusFolder" : self.get_status_dir(),
                "heartbeatFile" : self.get_heartbeat_file()
            }
        }]
        fileutil.write_file(self.get_env_file(),
                                 json.dumps(env))

    def get_target_version(self):
        version = self.get_version()
        update_policy = self.get_upgrade_policy()
        if update_policy is None or update_policy.lower() != 'auto':
            return version

        major = version.split('.')[0]
        if major is None:
            raise ExtensionError("Wrong version format: {0}".format(version))

        packages = [x for x in self.pkg_list.versions if x.version.startswith(major + ".")]
        packages = sorted(packages, key=lambda x: x.version, reverse=True)
        if len(packages) <= 0:
            raise ExtensionError("Can't find version: {0}.*".format(major))

        return packages[0].version

    def get_package_uris(self):
        version = self.get_version()
        packages = self.pkg_list.versions
        if packages is None:
            raise ExtensionError("Package uris is None.")

        for package in packages:
            if package.version == version:
                return package.uris

        raise ExtensionError("Can't get package uris for {0}.".format(version))

    def get_curr_op(self):
        return self.curr_op

    def get_name(self):
        return self.extension.name

    def get_version(self):
        return self.extension.properties.version

    def get_state(self):
        return self.extension.properties.state

    def get_seq_no(self):
        return self.settings.sequenceNumber

    def get_upgrade_policy(self):
        return self.extension.properties.upgradePolicy

    def get_full_name(self):
        return "{0}-{1}".format(self.get_name(), self.curr_version)

    def get_base_dir(self):
        return os.path.join(OSUTIL.get_lib_dir(), self.get_full_name())

    def get_status_dir(self):
        return os.path.join(self.get_base_dir(), "status")

    def get_status_file(self):
        return os.path.join(self.get_status_dir(),
                            "{0}.status".format(self.settings.sequenceNumber))

    def get_conf_dir(self):
        return os.path.join(self.get_base_dir(), 'config')

    def get_settings_file(self):
        return os.path.join(self.get_conf_dir(),
                            "{0}.settings".format(self.settings.sequenceNumber))

    def get_handler_state_file(self):
        return os.path.join(self.get_conf_dir(), 'HandlerState')

    def get_heartbeat_file(self):
        return os.path.join(self.get_base_dir(), 'heartbeat.log')

    def get_manifest_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerManifest.json')

    def get_env_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerEnvironment.json')

    def get_log_dir(self):
        return os.path.join(OSUTIL.get_ext_log_dir(), self.get_name(),
                            self.curr_version)

class HandlerEnvironment(object):
    def __init__(self, data):
        self.data = data

    def get_version(self):
        return self.data["version"]

    def get_log_dir(self):
        return self.data["handlerEnvironment"]["logFolder"]

    def get_conf_dir(self):
        return self.data["handlerEnvironment"]["configFolder"]

    def get_status_dir(self):
        return self.data["handlerEnvironment"]["statusFolder"]

    def get_heartbeat_file(self):
        return self.data["handlerEnvironment"]["heartbeatFile"]

class HandlerManifest(object):
    def __init__(self, data):
        if data is None or data['handlerManifest'] is None:
            raise ExtensionError('Malformed manifest file.')
        self.data = data

    def get_name(self):
        return self.data["name"]

    def get_version(self):
        return self.data["version"]

    def get_install_command(self):
        return self.data['handlerManifest']["installCommand"]

    def get_uninstall_command(self):
        return self.data['handlerManifest']["uninstallCommand"]

    def get_update_command(self):
        return self.data['handlerManifest']["updateCommand"]

    def get_enable_command(self):
        return self.data['handlerManifest']["enableCommand"]

    def get_disable_command(self):
        return self.data['handlerManifest']["disableCommand"]

    def is_reboot_after_install(self):
        #TODO handle reboot after install
        if "rebootAfterInstall" not in self.data['handlerManifest']:
            return False
        return self.data['handlerManifest']["rebootAfterInstall"]

    def is_report_heartbeat(self):
        if "reportHeartbeat" not in self.data['handlerManifest']:
            return False
        return self.data['handlerManifest']["reportHeartbeat"]

    def is_update_with_install(self):
        if "updateMode" not in self.data['handlerManifest']:
            return False
        if "updateMode" in self.data:
            return self.data['handlerManifest']["updateMode"].lower() == "updatewithinstall"
        return False
