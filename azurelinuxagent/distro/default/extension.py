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
import shutil
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.protocol as prot
from azurelinuxagent.metadata import AGENT_VERSION
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import ExtensionError
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.restutil as restutil
import azurelinuxagent.utils.shellutil as shellutil
from azurelinuxagent.utils.textutil import Version

#HandlerEnvironment.json schema version
HANDLER_ENVIRONMENT_VERSION = 1.0

VALID_EXTENSION_STATUS = ['transitioning', 'error', 'success', 'warning']

def validate_has_key(obj, key, fullname):
    if key not in obj:
        raise ExtensionError("Missing: {0}".format(fullname))

def validate_in_range(val, valid_range, name):
    if val not in valid_range:
        raise ExtensionError("Invalid {0}: {1}".format(name, val))

def parse_ext_substatus(substatus):
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
    status.name = substatus.get('name')
    status.status = substatus.get('status')
    status.code = substatus.get('code')
    status.message  =  substatus.get('formattedMessage').get('message')
    return status

def parse_ext_status(ext_status, data):
    if data is None or len(data) is None:
        return
    #Currently, only the first status will be reported
    data = data[0]
    #Check extension status format
    validate_has_key(data, 'status', 'status')
    status_data = data['status']
    validate_has_key(status_data, 'status', 'status/status')
    validate_has_key(status_data, 'operation', 'status/operation')
    validate_has_key(status_data, 'code', 'status/code')
    validate_has_key(status_data, 'name', 'status/name')
    validate_has_key(status_data, 'formattedMessage', 'status/formattedMessage')
    validate_has_key(status_data['formattedMessage'], 'lang',
                     'status/formattedMessage/lang')
    validate_has_key(status_data['formattedMessage'], 'message',
                     'status/formattedMessage/message')

    validate_in_range(status_data['status'], VALID_EXTENSION_STATUS,
                      'status/status')

    applied_time = status_data.get('configurationAppliedTime')
    ext_status.configurationAppliedTime = applied_time
    ext_status.operation = status_data.get('operation')
    ext_status.status = status_data.get('status')

    ext_status.code = status_data.get('code')
    ext_status.message =status_data['formattedMessage'].get('message')

    substatus_list = status_data.get('substatus')
    if substatus_list is None:
        return
    for substatus in substatus_list:
        ext_status.substatusList.append(parse_ext_substatus(substatus))

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
                if installed_version is None or \
                        Version(installed_version) < Version(version):
                    installed_version = version
    return installed_version

class ExtHandlersHandler(object):

    def process(self):
        try:
            protocol = prot.FACTORY.get_default_protocol()
            ext_handlers = protocol.get_ext_handlers()
        except prot.ProtocolError as e:
            add_event(name="WALA", is_success=False, message = text(e))
            return
        
        if ext_handlers.extHandlers is None or \
                len(ext_handlers.extHandlers) == 0:
            logger.info("No extensions to handle")
            return

        vm_status = prot.VMStatus()
        vm_status.vmAgent.version = AGENT_VERSION
        vm_status.vmAgent.status = "Ready"
        vm_status.vmAgent.message = "Guest Agent is running"

        for ext_handler in ext_handlers.extHandlers:
            #TODO handle extension in parallel
            try:
                pkg_list = protocol.get_ext_handler_pkgs(ext_handler)
            except prot.ProtocolError as e:
                add_event(name="WALA", is_success=False, message=text(e))
                continue
                
            handler_status = self.process_extension(ext_handler, pkg_list)
            if handler_status is not None:
                vm_status.vmAgent.extensionHandlers.append(handler_status)
        
        try:
            logger.info("Report vm agent status")
            protocol.report_vm_status(vm_status)
        except prot.ProtocolError as e:
            add_event(name="WALA", is_success=False, message = text(e))

    def process_extension(self, ext_handler, pkg_list):
        installed_version = get_installed_version(ext_handler.name)
        if installed_version is not None:
            handler = ExtHandlerInstance(ext_handler, pkg_list, 
                                         installed_version, installed=True)
        else:
            handler = ExtHandlerInstance(ext_handler, pkg_list,
                                         ext_handler.properties.version)
        handler.handle() 
        
        if handler.ext_status is not None:
            try:
                protocol = prot.FACTORY.get_default_protocol()
                protocol.report_ext_status(handler.name, handler.ext.name, 
                                           handler.ext_status)
            except prot.ProtocolError as e:
                add_event(name="WALA", is_success=False, message=text(e))
        
        return handler.handler_status

class ExtHandlerInstance(object):
    def __init__(self, ext_handler, pkg_list, curr_version, installed=False):
        self.ext_handler = ext_handler
        self.name = ext_handler.name
        self.version = ext_handler.properties.version
        self.pkg_list = pkg_list
        self.state = ext_handler.properties.state
        self.update_policy  = ext_handler.properties.upgradePolicy

        self.curr_version = curr_version
        self.enabled = False
        self.installed = installed
        self.lib_dir = OSUTIL.get_lib_dir()
        
        self.ext_status = prot.ExtensionStatus()
        self.handler_status = prot.ExtHandlerStatus()
        self.handler_status.name = self.name
        self.handler_status.version = self.curr_version

        self.ext = None
        #Currently, extension will have no more than 1 instance
        if len(ext_handler.properties.extensions) > 0:
            self.ext = ext_handler.properties.extensions[0]
            self.ext_status.sequenceNumber = self.ext.sequenceNumber
            self.handler_status.extensions = [self.ext.name]

        prefix = "[{0}]".format(self.get_full_name())
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)

    def init_logger(self):
        #Init logger appender for extension
        fileutil.mkdir(self.get_log_dir(), mode=0o644)
        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                 logger.LogLevel.INFO, log_file)

    def handle(self):
        self.init_logger()
        self.logger.info("Start processing extension handler")
        try: 
            self.handle_state()
            self.collect_ext_status()
            self.collect_handler_status()
        except ExtensionError as e:
            if self.ext_status is not None:
                self.ext_status.status = 'error'
            if self.handler_status is not None:
                self.handler_status.status = "NotReady"
                self.handler_status.message =  text(e)
            self.report_event(is_success=False, message=text(e))

        self.logger.info("Finished processing extension handler")

    def handle_state(self):
        if self.installed:
            self.logger.info("Installed version:{0}", self.curr_version)
            handler_state = self.get_state()
            self.enabled = (handler_state == "Ready")

        if self.state == 'enabled':
            self.handle_enable()
        elif self.state == 'disabled':
            self.handle_disable()
        elif self.state == 'uninstall':
            self.handle_disable()
            self.handle_uninstall()
        else:
            raise ExtensionError("Unknown state:{0}".format(self.state))

    def handle_enable(self):
        target_version = self.get_target_version()
        logger.info("Target version: {0}", target_version)
        if self.installed:
            if Version(target_version) > Version(self.curr_version):
                self.upgrade(target_version)
            elif Version(target_version) == Version(self.curr_version):
                self.enable()
            else:
                raise ExtensionError("A newer version is already installed")
        else:
            if Version(target_version) > Version(self.version):
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

    def report_event(self, is_success=True, message=""):
        add_event(name=self.name, op=self.ext_status.operation, 
                  is_success=is_success, message=message)

    def set_operation(self, operation):
        if self.ext_status.operation != WALAEventOperation.Upgrade:
            self.ext_status.operation = operation 

    def upgrade(self, target_version):
        self.logger.info("Upgrade from: {0} to {1}", self.curr_version,
                         target_version)
        self.set_operation(WALAEventOperation.Upgrade)

        old = self
        new = ExtHandlerInstance(self.ext_handler, self.pkg_list, 
                                 target_version)
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

    def download(self):
        self.logger.info("Download extension package")
        self.set_operation(WALAEventOperation.Download)

        uris = self.get_package_uris()
        package = None
        for uri in uris:
            try:
                resp = restutil.http_get(uri.uri, chk_proxy=True)
                if resp.status == restutil.httpclient.OK:
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
        self.report_event()

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
        self.set_state("NotReady")

        #Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self):
        self.logger.info("Enable extension.")
        self.set_operation(WALAEventOperation.Enable)

        man = self.load_manifest()
        self.launch_command(man.get_enable_command())
        self.set_state("Ready")

    def disable(self):
        self.logger.info("Disable extension.")
        self.set_operation(WALAEventOperation.Disable)

        man = self.load_manifest()
        self.launch_command(man.get_disable_command(), timeout=900)
        self.set_state("NotReady")

    def install(self):
        self.logger.info("Install extension.")
        self.set_operation(WALAEventOperation.Install)

        man = self.load_manifest()
        self.set_state("Installing")
        self.launch_command(man.get_install_command(), timeout=900)
        self.set_state("Ready")

    def uninstall(self):
        self.logger.info("Uninstall extension.")
        self.set_operation(WALAEventOperation.UnInstall)

        man = self.load_manifest()
        self.launch_command(man.get_uninstall_command())
        
        self.logger.info("Remove ext handler dir: {0}", self.get_base_dir())
        try:
            shutil.rmtree(self.get_base_dir())
        except IOError as e:
            raise ExtensionError("Failed to rm ext handler dir: {0}".format(e))
        self.handler_status = None
        self.ext_status = None

    def update(self):
        self.logger.info("Update extension.")
        self.set_operation(WALAEventOperation.Update)

        man = self.load_manifest()
        self.launch_command(man.get_update_command(), timeout=900)

    def collect_handler_status(self):
        self.logger.info("Collect extension handler status")
        if self.handler_status is None:
            return

        self.handler_status.status = self.get_state()
        man = self.load_manifest()
        if man.is_report_heartbeat():
            heartbeat = self.collect_heartbeat()
            if heartbeat is not None:
                self.handler_status.status = heartbeat['status']

    def collect_ext_status(self):
        self.logger.info("Collect extension status")
        if self.handler_status is None:
            return

        if self.ext is None:
            return

        ext_status_file = self.get_status_file()
        try:
            data_str = fileutil.read_file(ext_status_file)
            data = json.loads(data_str)
            parse_ext_status(self.ext_status, data)
        except IOError as e:
            raise ExtensionError("Failed to get status file: {0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed status file: {0}".format(e))

    def get_state(self):
        handler_state_file = self.get_handler_state_file()
        try:
            handler_state = fileutil.read_file(handler_state_file)
            return handler_state
        except IOError as e:
            raise ExtensionError("Failed to get handler status: {0}".format(e))

    def set_state(self, state):
        handler_state_file = self.get_handler_state_file()
        try:
            fileutil.write_file(handler_state_file, state)
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
        last_update=int(time.time() - os.stat(heartbeat_file).st_mtime)
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
        self.report_event()

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
        if self.ext is None:
            self.logger.verbose("Extension has no settings")
            return

        settings = {
            'publicSettings': self.ext.publicSettings,
            'protectedSettings': self.ext.privateSettings,
            'protectedSettingsCertThumbprint': self.ext.certificateThumbprint
        }
        ext_settings = {
            "runtimeSettings":[{
                "handlerSettings": settings
            }]
        }
        fileutil.write_file(self.get_settings_file(), json.dumps(ext_settings))

    def create_handler_env(self):
        env = [{
            "name": self.name,
            "version" : HANDLER_ENVIRONMENT_VERSION,
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
        version = self.version
        update_policy = self.update_policy
        if update_policy is None or update_policy.lower() != 'auto':
            return version

        major = version.split('.')[0]
        if major is None:
            raise ExtensionError("Wrong version format: {0}".format(version))

        packages = [x for x in self.pkg_list.versions \
                    if x.version.startswith(major + ".")]
        packages = sorted(packages, key=lambda x: Version(x.version), 
                          reverse=True)
        if len(packages) <= 0:
            raise ExtensionError("Can't find version: {0}.*".format(major))

        return packages[0].version

    def get_package_uris(self):
        version = self.curr_version
        packages = self.pkg_list.versions
        if packages is None:
            raise ExtensionError("Package uris is None.")

        for package in packages:
            if Version(package.version) == Version(version):
                return package.uris

        raise ExtensionError("Can't get package uris for {0}.".format(version))
    
    def get_full_name(self):
        return "{0}-{1}".format(self.name, self.curr_version)

    def get_base_dir(self):
        return os.path.join(OSUTIL.get_lib_dir(), self.get_full_name())

    def get_status_dir(self):
        return os.path.join(self.get_base_dir(), "status")

    def get_status_file(self):
        return os.path.join(self.get_status_dir(),
                            "{0}.status".format(self.ext.sequenceNumber))

    def get_conf_dir(self):
        return os.path.join(self.get_base_dir(), 'config')

    def get_settings_file(self):
        return os.path.join(self.get_conf_dir(),
                            "{0}.settings".format(self.ext.sequenceNumber))

    def get_handler_state_file(self):
        return os.path.join(self.get_conf_dir(), 'HandlerState')

    def get_heartbeat_file(self):
        return os.path.join(self.get_base_dir(), 'heartbeat.log')

    def get_manifest_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerManifest.json')

    def get_env_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerEnvironment.json')

    def get_log_dir(self):
        return os.path.join(OSUTIL.get_ext_log_dir(), self.name,
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
