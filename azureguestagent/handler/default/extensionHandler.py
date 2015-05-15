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
import traceback
import zipfile
import json
import subprocess
import azureguestagent.logger as logger
from azureguestagent.exception import ExtensionError
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.utils.restutil as restutil
from azureguestagent.utils.osutil import CurrOSUtil

ValidExtensionStatus = ['transitioning', 'error', 'success', 'warning']
ValidAggStatus = ['Installing', 'Ready', 'NotReady', 'Unresponsive']

#TODO when extension is disabled. Ready or NotReady?
HandlerStatusToAggStatus = {
        "uninstalled":"NotReady", 
        "installed":"Installing", 
        "disabled":"Ready",
        "enabled":"Ready"
}

class ExtensionHandler(object):

    def process(self, protocol):
        extSettings = protocol.getExtensions()
        for setting in extSettings:
            #TODO handle extension in parallel
            self.processExtension(protocol, setting) 
    
    def processExtension(self, protocol, setting)
        ext = LoadExtensionInstance(setting)
        if ext is None:
            ext = ExtensionInstance(setting, setting.getVersion())
        try:
            ext.initLog()
            ext.handle()
            aggStatus = ext.getAggStatus()
        except ExtensionError as e:
            logger.Error("Failed to handle extension: {0}-{1}, {2}", 
                         setting.getName(),
                         setting.getVersion(),
                         e)
            aggStatus = ext.createAggStatus("NotReady", {
                "status": "error",
                "operation": ext.getCurrOperation(), 
                "code" : -1, 
                "formattedMessage": {
                    "lang":"en-US",
                    "message": e.msg
                }
            });
        protocol.reportExtensionStatus(setting.getName(), 
                                       setting.getVersion(),
                                       aggStatus)


def ParseExtensionDirName(dirName):
    seprator = dirName.rfind('-')
    if seprator < 0:
        raise Exception("Invalid extenation dir name")
    return dirName[0:seprator], dirName[seprator + 1:]

def LoadExtensionInstance(setting):
    """
    Return the highest version instance with the same name
    """
    targetName = setting.getName()
    installedVersion = None
    libDir = CurrOSUtil.GetLibDir()
    ext = None
    for dirName in os.listdir(libDir):
        path = os.path.join(libDir, dirName)
        if os.path.isdir(path) and dirName.startswith(targetName):
            name, version = ParseExtensionDirName(dirName)
            #Here we need to ensure names are exactly the same.
            if name == targetName:
                if installedVersion is None or installedVersion < version:
                    installedVersion = version
    if installedVersion is not None:
        ext = ExtensionInstance(setting, installedVersion, installed=True)
    return ext

class ExtensionInstance(object):
    def __init__(self, setting, currVersion , installed=False):
        self.setting = setting
        self.currVersion = currVersion
        self.installed = installed
        self.enabled = False
        self.currOperation = None
        prefix = "[{0}]".format(self.getFullName())
        self.logger = logger.Logger(logger.DefaultLogger, prefix)
    
    def initLog(self):
        #Init logger appender for extension
        fileutil.CreateDir(self.getLogDir(), mode=0700)
        self.logger.addLoggerAppender(logger.AppenderConfig({
            'type' : 'FILE',
            'level' : 'INFO',
            'file_path' : os.path.join(self.getLogDir(), 
                                       "CommandExecution.log")
        }))
 
    def handle(self):
        self.logger.info("Process extension settings:")
        self.logger.info("  Name: {0}", self.setting.getName())
        self.logger.info("  Version: {0}", self.setting.getVersion())
        
        if self.installed:
            self.logger.info("Installed version:{0}", self.currVersion)
            handlerStatus = self.getHandlerStatus() 
            self.enabled = handlerStatus == "enabled"
            
        state = self.setting.getState()
        if state == 'enabled':
            self.handleEnable()
        elif state == 'disabled':
            self.handleDisable()
        elif state == 'uninstall':
            self.handleDisable()
            self.handleUninstall()
        else:
            raise ExtensionError("Unknown extension state:{0}".format(state))

    def handleEnable(self):
        targetVersion = self.getTargetVersion()
        if self.installed:
            if targetVersion > self.currVersion:
                self.upgrade(targetVersion)        
            elif targetVersion == self.currVersion:
                self.enable()
            else:
                #TODO downgrade is not allowed?
                raise ExtensionError("A newer version has already been installed")
        else:
            if targetVersion > self.setting.getVersion():
                #This will happen when auto upgrade policy is enabled
                self.logger.info("Auto upgrade to new version:{0}", 
                                 targetVersion)
                self.currVersion = targetVersion
            self.download()
            self.initExtensionDir()
            self.install()
            self.enable()

    def handleDisable(self):
        if not self.installed or not self.enabled:
            return
        self.disable()
  
    def handleUninstall(self):
        if not self.installed:
            return
        self.uninstall()

    def upgrade(self, targetVersion):
        self.logger.info("Upgrade from: {0} to {1}", 
                         self.setting.getVersion(),
                         targetVersion)
        old = self
        new = ExtensionInstance(self.setting, targetVersion)
        self.logger.info("Download new extension package")
        new.initLog()
        new.download()
        self.logger.info("Initialize new extension directory")
        new.initExtensionDir()

        old.disable()
        self.logger.info("Update new extension")
        new.update()
        old.uninstall()
        man = new.loadManifest()
        if man.isUpdateWithInstall():
            self.logger.info("Install new extension")
            new.install()
        self.logger.info("Enable new extension")
        new.enable()

    def download(self):
        self.logger.info("Download extension package")
        self.currOperation="Install"
        uris = self.getPackageUris()
        package = None
        for uri in uris:
            try:
                resp = restutil.HttpGet(uri)
                package = resp.read()
                break
            except restutil.HttpError as e:
                self.logger.warn("Failed download extension from: {0}", uri)

        if package is None:
            raise ExtensionError("Download extension failed")
        
        self.logger.info("Unpack extension package")
        packageFile = os.path.join(CurrOSUtil.GetLibDir(),
                                   os.path.basename(uri) + ".zip")
        fileutil.SetFileContents(packageFile, bytearray(package))
        zipfile.ZipFile(packageFile).extractall(self.getBaseDir())
    
    def initExtensionDir(self):
        self.logger.info("Initialize extension directory")
        #Save HandlerManifest.json
        manFile = fileutil.SearchForFile(self.getBaseDir(), 
                                         'HandlerManifest.json')
        man = fileutil.GetFileContents(manFile, removeBom=True)
        fileutil.SetFileContents(self.getManifestFile(), man)    

        #Create status and config dir
        statusDir = self.getStatusDir() 
        fileutil.CreateDir(statusDir, mode=0700)
        configDir = self.getConfigDir()
        fileutil.CreateDir(configDir, mode=0700)
        
        #Init handler state to uninstall
        self.setHandlerStatus("uninstalled")

        #Save HandlerEnvironment.json
        self.createHandlerEnvironment()

    def enable(self):
        self.logger.info("Enable extension.")
        self.currOperation="Enable"
        man = self.loadManifest()
        self.launchCommand(man.getEnableCommand())
        self.setHandlerStatus("enabled")

    def disable(self):
        self.logger.info("Disable extension.")
        self.currOperation="Disable"
        man = self.loadManifest()
        self.launchCommand(man.getDisableCommand(), timeout=900)
        self.setHandlerStatus("disabled")

    def install(self):
        self.logger.info("Install extension.")
        self.currOperation="Install"
        man = self.loadManifest()
        self.launchCommand(man.getInstallCommand(), timeout=900)
        self.setHandlerStatus("installed")

    def uninstall(self):
        self.logger.info("Uninstall extension.")
        self.currOperation="Uninstall"
        man = self.loadManifest()
        self.launchCommand(man.getUninstallCommand())
        self.setHandlerStatus("uninstalled")

    def update(self):
        self.logger.info("Update extension.")
        self.currOperation="Update"
        man = self.loadManifest()
        self.launchCommand(man.getUpdateCommand(), timeout=900)
    
    def createAggStatus(self, aggStatus, extStatus, heartbeat=None):
        aggregatedStatus = {
            'handlerVersion' : self.setting.getVersion(),
            'handlerName' : self.setting.getName(),
            'status' : aggStatus,
            'runtimeSettingsStatus' : {
                'settingsStatus' : extStatus,
                'sequenceNumber' : self.setting.getSeqNo()
            }
        }
        if heartbeat is not None:
            aggregatedStatus['code'] = heartbeat['code']
            aggregatedStatus['Message'] = heartbeat['Message']
        return aggregatedStatus

    def getAggStatus(self):
        self.logger.info("Collect extension status")
        extStatus = self.getExtensionStatus()
        self.validateExtensionStatus(extStatus) 

        self.logger.info("Collect handler status")
        handlerStatus = self.getHandlerStatus()
        aggStatus = HandlerStatusToAggStatus[handlerStatus]

        man = self.loadManifest() 
        if man.isReportHeartbeat():
            heartbeat = self.getHeartbeat()
            self.validateHeartbeat(heartbeat)
            aggStatus = heartbeat["status"]

        self.validateAggStatus(aggStatus)
        return self.createAggStatus(aggStatus, extStatus, heartbeat)

    def getExtensionStatus(self):
        extStatusFile = self.getStatusFile()
        try:
            extStatusJson = fileutil.GetFileContents(extStatusFile)
            extStatus = json.loads(extStatusJson)[0]
            return extStatus
        except IOError as e:
            raise ExtensionError("Failed to get status file: {0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed status file: {0}".format(e))

    def validateExtensionStatus(self, extStatus):
        #Check extension status format
        if 'status' not in extStatus:
            raise ExtensionError("Malformed status file: missing 'status'");
        if 'operation' not in extStatus:
            raise ExtensionError("Malformed status file: missing 'operation'");
        if 'code' not in extStatus:
            raise ExtensionError("Malformed status file: missing 'code'");
        if 'name' not in extStatus:
            raise ExtensionError("Malformed status file: missing 'name'");
        if 'formattedMessage' not in extStatus:
            raise ExtensionError("Malformed status file: missing 'name'");
        if 'lang' not in extStatus['formattedMessage']:
            raise ExtensionError("Malformed status file: missing 'lang'");
        if 'message' not in extStatus['formattedMessage']:
            raise ExtensionError("Malformed status file: missing 'message'");
        if extStatus['status'] not in ValidExtensionStatus:
            raise ExtensionError("Malformed status file: invalid 'status'");
        if type(extStatus['code']) != int:
            raise ExtensionError("Malformed status file: 'code' must be int");
   
    def getHandlerStatus(self):
        handlerStatus = "NotInstalled"
        handlerStatusFile = self.getHandlerStateFile()
        try:
            handlerStatus = fileutil.GetFileContents(handlerStatusFile)
            return handlerStatus
        except IOError as e:
            raise ExtensionError("Failed to get handler status: {0}".format(e))

    def setHandlerStatus(self, status):
        handlerStatusFile = self.getHandlerStateFile()
        try:
            fileutil.SetFileContents(handlerStatusFile, status)
        except IOError as e:
            raise ExtensionError("Failed to set handler status: {0}".format(e))

    def validateAggStatus(self, aggStatus):
        if aggStatus not in ValidAggStatus:
            raise ExtensionError(("Invalid aggretated status: "
                                  "{0}").format(aggStatus))

    def getHeartbeat(self):
        self.logger.info("Collect heart beat")
        heartbeatFile = os.path.join(CurrOSUtil.GetLibDir(), 
                                     ext.getHeartbeatFile())
        if not os.path.isfile(heartbeatFile):
            raise ExtensionError("Failed to get heart beat file")
        if not self.isResponsive(heartbeatFile):
            return {
                    "status": "Unresponsive",
                    "code": -1
                    "Message": ""
            }    
        try:
            heartbeatJson = fileutil.GetFileContents(heartbeatFile)
            heartbeat = json.loads()[0]['heartbeat']
        except IOError as e:
            raise ExtensionError("Failed to get heartbeat file:{0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed heartbeat file: {0}".format(e))
        return heartbeat

    def validateHeartbeat(self, heartbeat):
        if "status" not in heartbeat:
            raise ExtensionError("Malformed heartbeat file: missing 'status'")
        if "code" not in heartbeat:
            raise ExtensionError("Malformed heartbeat file: missing 'code'")
        if "Message" not in heartbeat:
            raise ExtensionError("Malformed heartbeat file: missing 'Message'")
       
    def isResponsive(self, heartbeatFile):
        lastUpdate=int(time.time()-os.stat(heartbeatFile).st_mtime)
        return  lastUpdate > 600    # not updated for more than 10 min

    def launchCommand(self, cmd, timeout=300):
        self.logger.info("Launch command:{0}", cmd)
        cmdPath = os.path.join(baseDir, cmd)
        os.chmod(cmdPath, "0100")
        self.updateSetting()
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(cmd, shell=True, cwd=baseDir, stdout=devnull)
        except Exception as e:
            #TODO do not catch all exception
            raise ExtensionError("Failed to launch: {0}, {1}".format(cmd, e))
    
        timeout = 300 
        retry = timeout / 5
        while retry > 0 and child.poll == None:
            time.sleep(5)
            retry -= 1
        if retry == 0:
            os.kill(child.pid, 9)
            raise ExtensionError("Timeout({0}): {1}".format(timeout, cmd))

        ret = child.wait()
        if ret == None or ret != 0:
            self.logger.error("Command {0} returned non-zero exit code: "
                              "({1})", cmd, ret)
            raise ExtensionError("Non-zero exit code: {0}, {1}".format(ret, cmd))
    
    def loadManifest(self):
        manFile = self.getManifestFile()
        try:
            data = json.loads(fileutil.GetFileContents(manFile))
        except IOError as e:
            raise ExtensionError('Failed to load manifest file.')
        except ValueError as e:
            raise ExtensionError('Malformed manifest file.')

        return HandlerManifest(data[0])


    def updateSetting(self):
        #TODO clear old .settings file
        fileutil.SetFileContents(self.setting.getSettingsFile(),
                                 json.dumps(self.setting.getSettings()))

    def createHandlerEnvironment(self):
        env = [{
            "version" : self.setting.getVersion(),
            "handlerEnvironment" : {
                "logFolder" : self.getLogDir(),
                "configFolder" : self.getConfigDir(),
                "statusFolder" : self.getStatusDir(),
                "heartbeatFile" : self.getHeartbeatFile()
            }
        }]
        fileutil.SetFileContents(self.getEnvironmentFile(),
                                 json.dumps(env))

    def getTargetVersion(self):
        version = self.setting.getVersion()
        updatePolicy = self.setting.getUpgradePolicy()
        if updatePolicy is None or updatePolicy.lower() != 'auto':
            return version
         
        major = version.split('.')[0]
        if major is None:
            raise ExtensionError("Wrong version format: {0}".format(version))

        versionUris = self.setting.getVersionUris()
        versionUris = filter(lambda x : x["version"].startswith(major + "."), 
                             versionUris)
        versionUris = sorted(versionUris, 
                             key=lambda x: x["version"], 
                             reverse=True)
        if len(versionUris) <= 0:
            raise ExtensionError("Can't find version: {0}.*".format(major))

        return versionUris[0]['version']

    def getPackageUris(self):
        versionUris = self.setting.getVersion()
        versionUris = self.setting.getVersionUris()
        if versionUris is None:
            raise ExtensionError("Package uris is None.")
        
        for versionUri in versionUris:
            if versionUri['version']== version:
                return versionUri['uris']

        raise ExtensionError("Can't get package uris for {0}.".format(version))
    
    def getCurrOperation(self):
        return self.currOperation

    def getFullName(self):
        return "{0}-{1}".format(self.setting.getName(), self.currVersion)

    def getBaseDir(self):
        return os.path.join(CurrOSUtil.GetLibDir(), self.getFullName()) 

    def getStatusDir(self):
        return os.path.join(self.getBaseDir(), "status")

    def getStatusFile(self):
        return os.path.join(self.getStatusDir(), 
                            "{0}.status".format(self.setting.getSeqNo()))

    def getConfigDir(self):
        return os.path.join(self.getBaseDir(), 'config')

    def getSettingsFile(self):
        return os.path.join(self.getConfigDir(), 
                            "{0}.settings".format(self.setting.getSeqNo()))

    def getHandlerStateFile(self):
        return os.path.join(self.getStatusDir(), 'HandlerState')

    def getHeartbeatFile(self):
        return os.path.join(self.getBaseDir(), 'heartbeat.log')

    def getManifestFile(self):
        return os.path.join(self.getBaseDir(), 'HandlerManifest.json')

    def getEnvironmentFile(self):
        return os.path.join(self.getBaseDir(), 'HandlerEnvironment.json')

    def getLogDir(self):
        return os.path.join(CurrOSUtil.GetExtLogDir(), 
                            self.setting.getName(), 
                            self.currVersion)

class HandlerEnvironment(object):
    def __init__(self, data):
        self.data = data
   
    def getVersion(self):
        return self.data["version"]

    def getLogDir(self):
        return self.data["handlerEnvironment"]["logFolder"]

    def getConfigDir(self):
        return self.data["handlerEnvironment"]["configFolder"]

    def getStatusDir(self):
        return self.data["handlerEnvironment"]["statusFolder"]

    def getHeartbeatFile(self):
        return self.data["handlerEnvironment"]["heartbeatFile"]

class HandlerManifest(object):
    def __init__(self, data):
        if data is None or data['handlerManifest'] is None:
            raise ExtensionError('Malformed manifest file.')
        self.data = data

    def getName(self):
        return self.data["name"]

    def getVersion(self):
        return self.data["version"]

    def getInstallCommand(self):
        return self.data['handlerManifest']["installCommand"]

    def getUninstallCommand(self):
        return self.data['handlerManifest']["uninstallCommand"]

    def getUpdateCommand(self):
        return self.data['handlerManifest']["updateCommand"]

    def getEnableCommand(self):
        return self.data['handlerManifest']["enableCommand"]

    def getDisableCommand(self):
        return self.data['handlerManifest']["disableCommand"]

    def isRebootAfterInstall(self):
        #TODO handle reboot after install
        if "rebootAfterInstall" not in self.data['handlerManifest']:
            return False
        return self.data['handlerManifest']["rebootAfterInstall"].lower() == "true"

    def isReportHeartbeat(self):
        if "reportHeartbeat" not in self.data['handlerManifest']:
            return False
        return self.data['handlerManifest']["reportHeartbeat"].lower() == "true"

    def isUpdateWithInstall(self):
        if "updateMode" not in self.data['handlerManifest']:
            return False
        if "updateMode" in self.data:
            return self.data['handlerManifest']["updateMode"].lower() == "updatewithinstall"
        return False
