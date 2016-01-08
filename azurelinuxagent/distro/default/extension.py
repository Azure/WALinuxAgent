# Microsoft Azure Linux Agent
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
import azurelinuxagent.conf as conf
import azurelinuxagent.logger as logger
from azurelinuxagent.event import add_event, WALAEventOperation
from azurelinuxagent.exception import ExtensionError, ProtocolError, HttpError
from azurelinuxagent.future import ustr
from azurelinuxagent.metadata import AGENT_VERSION
from azurelinuxagent.protocol.restapi import ExtHandlerStatus, ExtensionStatus, \
                                             ExtensionSubStatus, Extension, \
                                             VMStatus, ExtHandler, \
                                             get_properties, set_properties
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.restutil as restutil
import azurelinuxagent.utils.shellutil as shellutil
from azurelinuxagent.utils.textutil import Version

#HandlerEnvironment.json schema version
HANDLER_ENVIRONMENT_VERSION = 1.0

VALID_EXTENSION_STATUS = ['transitioning', 'error', 'success', 'warning']

VALID_HANDLER_STATUS = ['Ready', 'NotReady', "Installing", "Unresponsive"]

def validate_has_key(obj, key, fullname):
    if key not in obj:
        raise ExtensionError("Missing: {0}".format(fullname))

def validate_in_range(val, valid_range, name):
    if val not in valid_range:
        raise ExtensionError("Invalid {0}: {1}".format(name, val))

def parse_formatted_message(formatted_message):
    if formatted_message is None:
        return None
    validate_has_key(formatted_message, 'lang', 'formattedMessage/lang')
    validate_has_key(formatted_message, 'message', 'formattedMessage/message')
    return formatted_message.get('message')

def parse_ext_substatus(substatus):
    #Check extension sub status format
    validate_has_key(substatus, 'status', 'substatus/status')
    validate_in_range(substatus['status'], VALID_EXTENSION_STATUS,
                      'substatus/status')
    status = ExtensionSubStatus()
    status.name = substatus.get('name')
    status.status = substatus.get('status')
    status.code = substatus.get('code', 0)
    formatted_message = substatus.get('formattedMessage')
    status.message = parse_formatted_message(formatted_message)
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
    
    validate_in_range(status_data['status'], VALID_EXTENSION_STATUS,
                      'status/status')

    applied_time = status_data.get('configurationAppliedTime')
    ext_status.configurationAppliedTime = applied_time
    ext_status.operation = status_data.get('operation')
    ext_status.status = status_data.get('status')
    ext_status.code = status_data.get('code', 0)
    formatted_message = status_data.get('formattedMessage')
    ext_status.message = parse_formatted_message(formatted_message)
    substatus_list = status_data.get('substatus')
    if substatus_list is None:
        return
    for substatus in substatus_list:
        ext_status.substatusList.append(parse_ext_substatus(substatus))

class ExtHandlerState(object):
    NotInstalled = "NotInstalled"
    Installed = "Installed"
    Enabled = "Enabled"
    Disabled = "Disabled"
    Failed = "Failed"

class ExtHandlersHandler(object):
    def __init__(self, distro):
        self.distro = distro
        self.ext_handlers = None
        self.last_etag = None

    def run(self):
        ext_handlers, etag = None, None
        try:
            self.protocol = self.distro.protocol_util.get_protocol()
            ext_handlers, etag = self.protocol.get_ext_handlers()
        except ProtocolError as e:
            add_event(name="WALA", is_success=False, message=ustr(e))
            return

        if self.last_etag is not None and self.last_etag == etag:
            logger.verb("No change to ext handler config:{0}, skip", etag)
        else:
            logger.info("Handle new ext handler config")
            self.handle_ext_handlers(ext_handlers)
            self.last_etag = etag

        self.report_ext_handlers_status(ext_handlers)
   
    def handle_ext_handlers(self, ext_handlers):
        if ext_handlers.extHandlers is None or \
                len(ext_handlers.extHandlers) == 0:
            logger.info("No ext handler config found")
            return

        for ext_handler in ext_handlers.extHandlers:
            #TODO handle install in sequence, enable in parallel
            self.handle_ext_handler(ext_handler)
    
    def handle_ext_handler(self, ext_handler):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)
        try:
            state = ext_handler.properties.state
            ext_handler_i.logger.info("Expected handler state: {0}", state)
            if state == "enabled":
                self.handle_enable(ext_handler_i)
            elif state == u"disabled":
                self.handle_disable(ext_handler_i)
            elif state == u"uninstall":
                self.handle_uninstall(ext_handler_i)
            else:
                message = u"Unknown ext handler state:{0}".format(state)
                raise ExtensionError(message)
        except ExtensionError as e:
            ext_handler_i.set_handler_state(ExtHandlerState.Failed)
            ext_handler_i.set_handler_status(message=ustr(e), code=-1)
            ext_handler_i.report_event(message=ustr(e), is_success=False)
    
    def handle_enable(self, ext_handler_i):

        ext_handler_i.decide_version() 

        old_ext_handler_i = ext_handler_i.get_installed_ext_handler()
        if old_ext_handler_i is not None and \
           old_ext_handler_i.version_gt(ext_handler_i):
            raise ExtensionError(u"Downgrade not allowed")  

        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("Current handler state is: {0}", handler_state)
        if handler_state == ExtHandlerState.NotInstalled:
            ext_handler_i.set_handler_state(ExtHandlerState.NotInstalled)

            ext_handler_i.download()

            ext_handler_i.update_settings()

            if old_ext_handler_i is None:
                ext_handler_i.install()
            elif ext_handler_i.version_gt(old_ext_handler_i):
                old_ext_handler_i.disable()
                ext_handler_i.copy_status_files(old_ext_handler_i)
                ext_handler_i.update()
                old_ext_handler_i.uninstall()
                ext_handler_i.update_with_install()

        ext_handler_i.set_handler_state(ExtHandlerState.Installed)
            
        ext_handler_i.enable() 
        ext_handler_i.set_handler_state(ExtHandlerState.Enabled)
        ext_handler_i.set_handler_status(status="Ready", 
                                         message="Plugin enabled")

    def handle_disable(self, ext_handler_i):
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("Current handler state is: {0}", handler_state)
        if handler_state == ExtHandlerState.Enabled:
            ext_handler_i.disable()
            ext_handler_i.set_handler_state(ExtHandlerState.Disabled)
            ext_handler_i.set_handler_status(status="NotReady", 
                                             message="Plugin disabled")

    def handle_uninstall(self, ext_handler_i):
        handler_state = ext_handler_i.get_handler_state()
        ext_handler_i.logger.info("Current handler state is: {0}", handler_state)
        if handler_state != ExtHandlerState.NotInstalled:
            if handler_state == ExtHandlerState.Enabled:
                ext_handler_i.disable()
                ext_handler_i.set_handler_state(ExtHandlerState.Disabled)
                ext_handler_i.set_handler_status(status="NotReady", 
                                                 message="Plugin disabled")
            ext_handler_i.uninstall()
    
    def report_ext_handlers_status(self, ext_handlers):
        """Go thru handler_state dir, collect and report status"""
        vm_status = VMStatus()
        vm_status.vmAgent.version = AGENT_VERSION
        vm_status.vmAgent.status = "Ready"
        vm_status.vmAgent.message = "Guest Agent is running"

        if ext_handlers is not None:
            for ext_handler in ext_handlers.extHandlers:
                try:
                    self.report_ext_handler_status(vm_status, ext_handler)
                except ExtensionError as e:
                    add_event(name="WALA", is_success=False, message=ustr(e))
        
        logger.verb("Report vm agent status")
        try:
            self.protocol.report_vm_status(vm_status)
        except ProtocolError as e:
            message = "Failed to report ext handler status: {0}".format(e)
            add_event(name="WALA", is_success=False, message=message)

    def report_ext_handler_status(self, vm_status, ext_handler):
        ext_handler_i = ExtHandlerInstance(ext_handler, self.protocol)
        
        handler_status = ext_handler_i.get_handler_status() 
        if handler_status is None:
            return

        handler_state = ext_handler_i.get_handler_state()
        if handler_state == ExtHandlerState.Enabled:
            try:
                active_exts = ext_handler_i.report_ext_status()
                handler_status.extensions.extend(active_exts)
            except ExtensionError as e:
                ext_handler_i.set_handler_status(message=ustr(e), code=-1)

            try:
                heartbeat = ext_handler_i.collect_heartbeat()
                if heartbeat is not None:
                    handler_status.status = heartbeat.get('status')
            except ExtensionError as e:
                ext_handler_i.set_handler_status(message=ustr(e), code=-1)

        vm_status.vmAgent.extensionHandlers.append(handler_status)
        
class ExtHandlerInstance(object):
    def __init__(self, ext_handler, protocol):
        self.ext_handler = ext_handler
        self.protocol = protocol
        self.operation = None
        self.pkg = None

        prefix = "[{0}]".format(self.get_full_name())
        self.logger = logger.Logger(logger.DEFAULT_LOGGER, prefix)

        fileutil.mkdir(self.get_log_dir(), mode=0o744)
        log_file = os.path.join(self.get_log_dir(), "CommandExecution.log")
        self.logger.add_appender(logger.AppenderType.FILE,
                                 logger.LogLevel.INFO, log_file)

    def decide_version(self):
        """
        If auto-upgrade, get the largest public extension version under 
        the requested major version family of currently installed plugin version

        Else, get the highest hot-fix for requested version, 
        """
        self.logger.info("Decide which version to use")
        try:
            pkg_list = self.protocol.get_ext_handler_pkgs(self.ext_handler)
        except ProtocolError as e:
            raise ExtensionError("Failed to get ext handler pkgs", e)

        version = self.ext_handler.properties.version 
        update_policy = self.ext_handler.properties.upgradePolicy
        
        version_frag = version.split('.')
        if len(version_frag) < 2:
            raise ExtensionError("Wrong version format: {0}".format(version))

        version_prefix = None
        if update_policy is not None and update_policy == 'auto':
            version_prefix = "{0}.".format(version_frag[0])
        else:
            version_prefix = "{0}.{1}.".format(version_frag[0], version_frag[1])
        
        packages = [x for x in pkg_list.versions \
                    if x.version.startswith(version_prefix) or \
                       x.version == version]
        
        packages = sorted(packages, key=lambda x: Version(x.version), 
                          reverse=True)

        if len(packages) <= 0:
            raise ExtensionError("Failed to find and valid extension package")
        self.pkg = packages[0]
        self.ext_handler.properties.version = packages[0].version
        self.logger.info("Use version: {0}", self.pkg.version)

    def version_gt(self, other):
        self_version = self.ext_handler.properties.version
        other_version = other.ext_handler.properties.version
        return Version(self_version) > Version(other_version)

    def get_installed_ext_handler(self):
        lastest_version = None
        ext_handler_name = self.ext_handler.name

        for dir_name in os.listdir(conf.get_lib_dir()):
            path = os.path.join(conf.get_lib_dir(), dir_name)
            if os.path.isdir(path) and dir_name.startswith(ext_handler_name):
                seprator = dir_name.rfind('-')
                if seprator < 0:
                    continue
                installed_name = dir_name[0: seprator]
                installed_version = dir_name[seprator + 1:] 
                if installed_name != ext_handler_name:
                    continue
                if lastest_version is None or \
                        Version(lastest_version) < Version(installed_version):
                   lastest_version = installed_version

        if lastest_version is None:
            return None
        
        data = get_properties(self.ext_handler)
        old_ext_handler = ExtHandler()
        set_properties("ExtHandler", old_ext_handler, data)
        old_ext_handler.properties.version = lastest_version
        return ExtHandlerInstance(old_ext_handler, self.protocol)
    
    def copy_status_files(self, old_ext_handler_i):
        self.logger.info("Copy status files from old plugin to new")
        old_ext_dir = old_ext_handler_i.get_base_dir()
        new_ext_dir = self.get_base_dir()

        old_ext_mrseq_file = os.path.join(old_ext_dir, "mrseq")
        if os.path.isfile(old_ext_mrseq_file):
            shutil.copy2(old_ext_mrseq_file, new_ext_dir)

        old_ext_status_dir = old_ext_handler_i.get_status_dir()
        new_ext_status_dir = self.get_status_dir()

        if os.path.isdir(old_ext_status_dir):
            for status_file in os.listdir(old_ext_status_dir):
                status_file = os.path.join(old_ext_status_dir, status_file)
                if os.path.isfile(status_file):
                    shutil.copy2(status_file, new_ext_status_dir)
    
    def set_operation(self, op):
        self.operation = op

    def report_event(self, message="", is_success=True):
        add_event(name=self.ext_handler.name, message=message, 
                  op=self.operation, is_success=is_success)

    def download(self):
        self.logger.info("Download extension package")
        self.set_operation(WALAEventOperation.Download)
        if self.pkg is None:
            raise ExtensionError("No package uri found")
        
        package = None
        for uri in self.pkg.uris:
            try:
                package = self.protocol.download_ext_handler_pkg(uri.uri)
            except ProtocolError as e: 
                logger.warn("Failed download extension: {0}", e)
        
        if package is None:
            raise ExtensionError("Failed to download extension")

        self.logger.info("Unpack extension package")
        pkg_file = os.path.join(conf.get_lib_dir(),
                                os.path.basename(uri.uri) + ".zip")
        fileutil.write_file(pkg_file, bytearray(package), asbin=True)
        zipfile.ZipFile(pkg_file).extractall(self.get_base_dir())
        chmod = "find {0} -type f | xargs chmod u+x".format(self.get_base_dir())
        shellutil.run(chmod)
        self.report_event(message="Download succeeded")

        self.logger.info("Initialize extension directory")
        #Save HandlerManifest.json
        man_file = fileutil.search_file(self.get_base_dir(),
                                        'HandlerManifest.json')

        if man_file is None:
            raise ExtensionError("HandlerManifest.json not found")

        man = fileutil.read_file(man_file, remove_bom=True)
        fileutil.write_file(self.get_manifest_file(), man)

        #Create status and config dir
        status_dir = self.get_status_dir()
        fileutil.mkdir(status_dir, mode=0o700)
        conf_dir = self.get_conf_dir()
        fileutil.mkdir(conf_dir, mode=0o700)

        #Save HandlerEnvironment.json
        self.create_handler_env()

    def enable(self):
        self.logger.info("Enable extension.")
        self.set_operation(WALAEventOperation.Enable)

        man = self.load_manifest()
        self.launch_command(man.get_enable_command())

    def disable(self):
        self.logger.info("Disable extension.")
        self.set_operation(WALAEventOperation.Disable)

        man = self.load_manifest()
        self.launch_command(man.get_disable_command(), timeout=900)

    def install(self):
        self.logger.info("Install extension.")
        self.set_operation(WALAEventOperation.Install)

        man = self.load_manifest()
        self.launch_command(man.get_install_command(), timeout=900)

    def uninstall(self):
        self.logger.info("Uninstall extension.")
        self.set_operation(WALAEventOperation.UnInstall)
        
        try:
            man = self.load_manifest()
            self.launch_command(man.get_uninstall_command())
        except ExtensionError as e:
            self.report_event(message=ustr(e), is_success=False)

        self.logger.info("Remove ext handler dir: {0}", self.get_base_dir())
        try:
            shutil.rmtree(self.get_base_dir())
            shutil.rmtree(self.get_handler_state_dir())
        except IOError as e:
            raise ExtensionError("Failed to rm ext handler dir: {0}".format(e))

    def update(self):
        self.logger.info("Update extension.")
        self.set_operation(WALAEventOperation.Update)
        
        man = self.load_manifest()
        self.launch_command(man.get_update_command(), timeout=900)
    
    def update_with_install(self):
        man = self.load_manifest()
        if man.is_update_with_install():
            self.install()
        else:
            self.logger.info("UpdateWithInstall not set. "
                             "Skip install during upgrade.")

    def collect_ext_status(self, ext):
        self.logger.verb("Collect extension status")
        status_dir = self.get_status_dir()
        ext_status = None
        ext_status_file = "{0}.status".format(ext.sequenceNumber)
        ext_status_file = os.path.join(status_dir, ext_status_file)
        try:
            data_str = fileutil.read_file(ext_status_file)
            data = json.loads(data_str)
            ext_status = ExtensionStatus()
            parse_ext_status(ext_status, data)
            return ext_status
        except IOError as e:
            raise ExtensionError(u"Failed to get status file", e)
        except ValueError as e:
            raise ExtensionError(u"Malformed status file", e)
    
    def report_ext_status(self):
        active_exts = []
        for ext in self.ext_handler.properties.extensions:
            try:
                ext_status = self.collect_ext_status(ext)
            except ExtensionError as e:
                ext_status = ExtensionStatus(message=str(e), code=-1, 
                                             status="error")
            try:
                self.protocol.report_ext_status(self.ext_handler.name, ext.name, 
                                                ext_status)
                active_exts.append(ext.name)
            except ProtocolError as e:
                self.logger.error(u"Failed to report extension status: {0}", e)
        return active_exts

    def collect_heartbeat(self):
        man = self.load_manifest()
        if not man.is_report_heartbeat():
            return
        heartbeat_file = os.path.join(conf.get_lib_dir(),
                                      self.get_heartbeat_file())

        self.logger.info("Collect heart beat")
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

        self.report_event(message="Launch command succeeded: {0}".format(cmd))

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
        if self.ext_handler.properties.extensions is None:
            self.logger.verb("Extension has no settings")
            return
        
        for ext in self.ext_handler.properties.extensions:
            settings = {
                'publicSettings': ext.publicSettings,
                'protectedSettings': ext.protectedSettings,
                'protectedSettingsCertThumbprint': ext.certificateThumbprint
            }
            ext_settings = {
                "runtimeSettings":[{
                    "handlerSettings": settings
                }]
            }
            settings_file = "{0}.settings".format(ext.sequenceNumber)
            settings_file = os.path.join(self.get_conf_dir(), settings_file)
            fileutil.write_file(settings_file, json.dumps(ext_settings))

    def create_handler_env(self):
        env = [{
            "name": self.ext_handler.name,
            "version" : HANDLER_ENVIRONMENT_VERSION,
            "handlerEnvironment" : {
                "logFolder" : self.get_log_dir(),
                "configFolder" : self.get_conf_dir(),
                "statusFolder" : self.get_status_dir(),
                "heartbeatFile" : self.get_heartbeat_file()
            }
        }]
        fileutil.write_file(self.get_env_file(), json.dumps(env))
    
    def get_handler_state_dir(self):
        return os.path.join(conf.get_lib_dir(), "handler_state", 
                            self.get_full_name())

    def set_handler_state(self, handler_state):
        state_dir = self.get_handler_state_dir()
        if not os.path.exists(state_dir):
            fileutil.mkdir(state_dir, 0o700)
        
        try:
            state_file = os.path.join(state_dir, "state")
            fileutil.write_file(state_file, handler_state)
        except IOError as e:
            self.logger.error("Failed to set state: {0}", e)
    
    def get_handler_state(self):
        state_dir = self.get_handler_state_dir()
        state_file = os.path.join(state_dir, "state")
        if not os.path.isfile(state_file):
            return ExtHandlerState.NotInstalled

        try:
            return fileutil.read_file(state_file)
        except IOError as e:
            self.logger.error("Failed to get state: {0}", e)
    
    def set_handler_status(self, status="NotReady", message="", 
                           code=0):
        state_dir = self.get_handler_state_dir()
        if not os.path.exists(state_dir):
            fileutil.mkdir(state_dir, 0o700)
        
        handler_status = ExtHandlerStatus()
        handler_status.name = self.ext_handler.name
        handler_status.version = self.ext_handler.properties.version
        handler_status.message = message
        handler_status.code = code
        handler_status.status = status
        status_file = os.path.join(state_dir, "status")

        try:
            fileutil.write_file(status_file, 
                                json.dumps(get_properties(handler_status)))
        except (IOError, ValueError, ProtocolError) as e:
            self.logger.error("Failed to save handler status: {0}", e)
        
    def get_handler_status(self):
        state_dir = self.get_handler_state_dir()
        status_file = os.path.join(state_dir, "status")
        if not os.path.isfile(status_file):
            return None
        
        try:
            data = json.loads(fileutil.read_file(status_file))
            handler_status = ExtHandlerStatus() 
            set_properties("ExtHandlerStatus", handler_status, data)
            return handler_status
        except (IOError, ValueError) as e:
            self.logger.error("Failed to get handler status: {0}", e)

    def get_full_name(self):
        return "{0}-{1}".format(self.ext_handler.name, 
                                self.ext_handler.properties.version)
   
    def get_base_dir(self):
        return os.path.join(conf.get_lib_dir(), self.get_full_name())

    def get_status_dir(self):
        return os.path.join(self.get_base_dir(), "status")

    def get_conf_dir(self):
        return os.path.join(self.get_base_dir(), 'config')

    def get_heartbeat_file(self):
        return os.path.join(self.get_base_dir(), 'heartbeat.log')

    def get_manifest_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerManifest.json')

    def get_env_file(self):
        return os.path.join(self.get_base_dir(), 'HandlerEnvironment.json')

    def get_log_dir(self):
        return os.path.join(conf.get_ext_log_dir(), self.ext_handler.name,
                            self.ext_handler.properties.version)

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
        """
        Deprecated
        """
        return False

    def is_report_heartbeat(self):
        return self.data['handlerManifest'].get('reportHeartbeat', False)

    def is_update_with_install(self):
        update_mode = self.data['handlerManifest'].get('updateMode')
        return update_mode is not None and \
               update_mode.low() == "updatewithinstall"
