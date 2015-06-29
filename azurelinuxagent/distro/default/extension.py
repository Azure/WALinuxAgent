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
from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.protocol as prot
from azurelinuxagent.event import AddExtensionEvent, WALAEventOperation
from azurelinuxagent.exception import ExtensionError
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.restutil as restutil
import azurelinuxagent.utils.shellutil as shellutil

ValidExtensionStatus = ['transitioning', 'error', 'success', 'warning']

def validate_has_key(obj, key, fullName):
    if key not in obj:
        raise ExtensionError("Missing: {0}".format(fullName))

def validate_in_range(val, validRange, name):
    if val not in validRange:
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

    validate_in_range(substatus['status'], ValidExtensionStatus, 
                      'substatus/status')
    status = prot.ExtensionSubStatus()
    status.name = try_get(substatus, 'name')
    status.status = try_get(substatus, 'status')
    status.code = try_get(substatus, 'code')
    status.message = try_get(substatus['formattedMessage'], 'message')
    return status

def extension_status_to_v2(extStatus, seqNo):
    #Check extension status format
    validate_has_key(extStatus, 'status', 'status')
    validate_has_key(extStatus['status'], 'status', 'status/status')
    validate_has_key(extStatus['status'], 'operation', 'status/operation')
    validate_has_key(extStatus['status'], 'code', 'status/code')
    #TODO are those fields all mandatory
    validate_has_key(extStatus['status'], 'name', 'status/name')
    validate_has_key(extStatus['status'], 'formattedMessage', 
                     'status/formattedMessage')
    validate_has_key(extStatus['status']['formattedMessage'], 'lang', 
                     'status/formattedMessage/lang')
    validate_has_key(extStatus['status']['formattedMessage'], 'message', 
                     'status/formattedMessage/message')

    validate_in_range(extStatus['status']['status'], ValidExtensionStatus,
                      'status/status')
    
    status = prot.ExtensionStatus()
    status.name = try_get(extStatus['status'], 'name')
    status.configurationAppliedTime = try_get(extStatus['status'], 
                                              'configurationAppliedTime')
    status.operation = try_get(extStatus['status'], 'operation')
    status.status = try_get(extStatus['status'], 'status')
    status.code = try_get(extStatus['status'], 'code')
    status.message = try_get(extStatus['status']['formattedMessage'], 'message')
    status.sequenceNumber = seqNo

    substatusList = try_get(extStatus['status'], 'substatus', [])
    for substatus in substatusList:
        status.substatusList.extend(extension_sub_status_to_v2(substatus))
    return status

class ExtensionsHandler(object):

    def process(self):
        protocol = prot.Factory.getDefaultProtocol()
        extList = protocol.getExtensions()
        
        handlerStatusList = []
        for extension in extList.extensions:
            #TODO handle extension in parallel
            packageList = protocol.getExtensionPackages(extension)
            handlerStatus = self.processExtension(extension, packageList) 
            handlerStatusList.append(handlerStatus)

        return handlerStatusList
    
    def processExtension(self, extension, packageList):
        installedVersion = GetInstalledExtensionVersion(extension.name)
        if installedVersion is not None:
            ext = ExtensionInstance(extension, packageList,
                                    installedVersion, installed=True)
        else:
            ext = ExtensionInstance(extension, packageList, 
                                    extension.properties.version)
        try:
            ext.initLog()
            ext.handle()
            status = ext.collectHandlerStatus()
        except ExtensionError as e:
            logger.Error("Failed to handle extension: {0}-{1}\n {2}", 
                         ext.getName(), ext.getVersion(), e)
            AddExtensionEvent(name=ext.getName(), isSuccess=False,
                              op=ext.getCurrOperation(), message = str(e))
            extStatus = prot.ExtensionStatus(status='error', code='-1', 
                                             operation = ext.getCurrOperation(),
                                             message = str(e),
                                             sequenceNumber = ext.getSeqNo())
            status = ext.createHandlerStatus(extStatus)
            status.status = "NotReady"
        return status

def ParseExtensionDirName(dirName):
    """
    Parse installed extension dir name. Sample: ExtensionName-Version/
    """
    seprator = dirName.rfind('-')
    if seprator < 0:
        raise ExtensionError("Invalid extenation dir name")
    return dirName[0:seprator], dirName[seprator + 1:]

def GetInstalledExtensionVersion(targetName):
    """
    Return the highest version instance with the same name
    """
    installedVersion = None
    libDir = OSUtil.GetLibDir()
    for dirName in os.listdir(libDir):
        path = os.path.join(libDir, dirName)
        if os.path.isdir(path) and dirName.startswith(targetName):
            name, version = ParseExtensionDirName(dirName)
            #Here we need to ensure names are exactly the same.
            if name == targetName:
                if installedVersion is None or installedVersion < version:
                    installedVersion = version
    return installedVersion

class ExtensionInstance(object):
    def __init__(self, extension, packageList, currVersion, installed=False):
        self.extension = extension
        self.packageList = packageList
        self.currVersion = currVersion
        self.libDir = OSUtil.GetLibDir()
        self.installed = installed
        self.settings = None
        
        #Extension will have no more than 1 settings instance
        if len(extension.properties.extensions) > 0:
            self.settings = extension.properties.extensions[0]
        self.enabled = False
        self.currOperation = None

        prefix = "[{0}]".format(self.getFullName())
        self.logger = logger.Logger(logger.DefaultLogger, prefix)
    
    def initLog(self):
        #Init logger appender for extension
        fileutil.CreateDir(self.getLogDir(), mode=0700)
        logFile = os.path.join(self.getLogDir(), "CommandExecution.log")
        self.logger.addLoggerAppender(logger.AppenderType.FILE,
                                      logger.LogLevel.INFO, logFile)
 
    def handle(self):
        self.logger.info("Process extension settings:")
        self.logger.info("  Name: {0}", self.getName())
        self.logger.info("  Version: {0}", self.getVersion())
        
        if self.installed:
            self.logger.info("Installed version:{0}", self.currVersion)
            handlerStatus = self.getHandlerStatus() 
            self.enabled = (handlerStatus == "Ready")
            
        state = self.getState()
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
            if targetVersion > self.getVersion():
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
        self.logger.info("Upgrade from: {0} to {1}", self.currVersion,
                         targetVersion)
        self.currOperation=WALAEventOperation.Upgrade
        old = self
        new = ExtensionInstance(self.extension, self.packageList, targetVersion)
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
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")

    def download(self):
        self.logger.info("Download extension package")
        self.currOperation=WALAEventOperation.Download
        uris = self.getPackageUris()
        package = None
        for uri in uris:
            try:
                resp = restutil.HttpGet(uri.uri, chkProxy=True)
                package = resp.read()
                break
            except restutil.HttpError as e:
                self.logger.warn("Failed download extension from: {0}", uri.uri)

        if package is None:
            raise ExtensionError("Download extension failed")
        
        self.logger.info("Unpack extension package")
        pkgFile = os.path.join(self.libDir, os.path.basename(uri.uri) + ".zip")
        fileutil.SetFileContents(pkgFile, bytearray(package))
        zipfile.ZipFile(pkgFile).extractall(self.getBaseDir())
        chmod = "find {0} -type f | xargs chmod u+x".format(self.getBaseDir())
        shellutil.Run(chmod)
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")
    
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
        self.setHandlerStatus("NotReady")

        #Save HandlerEnvironment.json
        self.createHandlerEnvironment()

    def enable(self):
        self.logger.info("Enable extension.")
        self.currOperation=WALAEventOperation.Enable
        man = self.loadManifest()
        self.launchCommand(man.getEnableCommand())
        self.setHandlerStatus("Ready")
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")

    def disable(self):
        self.logger.info("Disable extension.")
        self.currOperation=WALAEventOperation.Disable
        man = self.loadManifest()
        self.launchCommand(man.getDisableCommand(), timeout=900)
        self.setHandlerStatus("Ready")
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")

    def install(self):
        self.logger.info("Install extension.")
        self.currOperation=WALAEventOperation.Install
        man = self.loadManifest()
        self.setHandlerStatus("Installing")
        self.launchCommand(man.getInstallCommand(), timeout=900)
        self.setHandlerStatus("Ready")
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")

    def uninstall(self):
        self.logger.info("Uninstall extension.")
        self.currOperation=WALAEventOperation.UnInstall
        man = self.loadManifest()
        self.launchCommand(man.getUninstallCommand())
        self.setHandlerStatus("NotReady")
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")

    def update(self):
        self.logger.info("Update extension.")
        self.currOperation=WALAEventOperation.Update
        man = self.loadManifest()
        self.launchCommand(man.getUpdateCommand(), timeout=900)
        AddExtensionEvent(name=self.getName(), isSuccess=True,
                          op=self.currOperation, message="")
    
    def createHandlerStatus(self, extStatus, heartbeat=None):
        status = prot.ExtensionHandlerStatus()
        status.handlerName = self.getName()
        status.handlerVersion = self.getVersion()
        status.status = self.getHandlerStatus()
        status.extensionStatusList.append(extStatus)
        return status 

    def collectHandlerStatus(self):
        man = self.loadManifest() 
        heartbeat=None
        if man.isReportHeartbeat():
            heartbeat = self.getHeartbeat()
        extStatus = self.getExtensionStatus()
        status= self.createHandlerStatus(extStatus, heartbeat) 
        status.status = self.getHandlerStatus()
        if heartbeat is not None:
            status.status = heartbeat['status']
        status.extensionStatusList.append(extStatus)
        return status

    def getExtensionStatus(self):
        extStatusFile = self.getStatusFile()
        try:
            extStatusJson = fileutil.GetFileContents(extStatusFile)
            extStatus = json.loads(extStatusJson)
        except IOError as e:
            raise ExtensionError("Failed to get status file: {0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed status file: {0}".format(e))
        return extension_status_to_v2(extStatus[0], 
                                      self.settings.sequenceNumber)
   
    def getHandlerStatus(self):
        handlerStatus = "uninstalled"
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

    def getHeartbeat(self):
        self.logger.info("Collect heart beat")
        heartbeatFile = os.path.join(OSUtil.GetLibDir(), 
                                     self.getHeartbeatFile())
        if not os.path.isfile(heartbeatFile):
            raise ExtensionError("Failed to get heart beat file")
        if not self.isResponsive(heartbeatFile):
            return {
                    "status": "Unresponsive",
                    "code": -1,
                    "message": "Extension heartbeat is not responsive"
            }    
        try:
            heartbeatJson = fileutil.GetFileContents(heartbeatFile)
            heartbeat = json.loads(heartbeatJson)[0]['heartbeat']
        except IOError as e:
            raise ExtensionError("Failed to get heartbeat file:{0}".format(e))
        except ValueError as e:
            raise ExtensionError("Malformed heartbeat file: {0}".format(e))
        return heartbeat

    def isResponsive(self, heartbeatFile):
        lastUpdate=int(time.time()-os.stat(heartbeatFile).st_mtime)
        return  lastUpdate > 600    # not updated for more than 10 min

    def launchCommand(self, cmd, timeout=300):
        self.logger.info("Launch command:{0}", cmd)
        baseDir = self.getBaseDir()
        self.updateSettings()
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(baseDir + "/" + cmd, shell=True,
                                     cwd=baseDir, stdout=devnull)
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
    
    def loadManifest(self):
        manFile = self.getManifestFile()
        try:
            data = json.loads(fileutil.GetFileContents(manFile))
        except IOError as e:
            raise ExtensionError('Failed to load manifest file.')
        except ValueError as e:
            raise ExtensionError('Malformed manifest file.')

        return HandlerManifest(data[0])


    def updateSettings(self):
        if self.settings is None:
            self.logger.verbose("Extension has no settings")
            return

        handlerSettings = {
            'publicSettings': self.settings.publicSettings,
            'protectedSettings': self.settings.privateSettings,
            'protectedSettingsCertThumbprint': self.settings.certificateThumbprint
        }
        extSettings = {
            "runtimeSettings":[{
                "handlerSettings": handlerSettings
            }]
        }
        fileutil.SetFileContents(self.getSettingsFile(), json.dumps(extSettings))

        latest = os.path.join(self.getConfigDir(), "latest")
        fileutil.SetFileContents(latest, self.settings.sequenceNumber)

    def createHandlerEnvironment(self):
        env = [{
            "name": self.getName(),
            "version" : self.getVersion(),
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
        version = self.getVersion()
        updatePolicy = self.getUpgradePolicy()
        if updatePolicy is None or updatePolicy.lower() != 'auto':
            return version
         
        major = version.split('.')[0]
        if major is None:
            raise ExtensionError("Wrong version format: {0}".format(version))

        packages = filter(lambda x : x.version.startswith(major + "."), 
                          self.packageList.versions)
        packages = sorted(packages, key=lambda x: x.version, reverse=True)
        if len(packages) <= 0:
            raise ExtensionError("Can't find version: {0}.*".format(major))

        return packages[0].version

    def getPackageUris(self):
        version = self.getVersion()
        packages = self.packageList.versions
        if packages is None:
            raise ExtensionError("Package uris is None.")
        
        for package in packages:
            if package.version == version:
                return package.uris

        raise ExtensionError("Can't get package uris for {0}.".format(version))
    
    def getCurrOperation(self):
        return self.currOperation
    
    def getName(self):
        return self.extension.name

    def getVersion(self):
        return self.extension.properties.version

    def getState(self):
        return self.extension.properties.state

    def getSeqNo(self):
        return self.settings.sequenceNumber
    
    def getUpgradePolicy(self):
        return self.extension.properties.upgradePolicy
    
    def getFullName(self):
        return "{0}-{1}".format(self.getName(), self.currVersion)

    def getBaseDir(self):
        return os.path.join(OSUtil.GetLibDir(), self.getFullName()) 

    def getStatusDir(self):
        return os.path.join(self.getBaseDir(), "status")

    def getStatusFile(self):
        return os.path.join(self.getStatusDir(), 
                            "{0}.status".format(self.settings.sequenceNumber))

    def getConfigDir(self):
        return os.path.join(self.getBaseDir(), 'config')

    def getSettingsFile(self):
        return os.path.join(self.getConfigDir(), 
                            "{0}.settings".format(self.settings.sequenceNumber))

    def getHandlerStateFile(self):
        return os.path.join(self.getConfigDir(), 'HandlerState')

    def getHeartbeatFile(self):
        return os.path.join(self.getBaseDir(), 'heartbeat.log')

    def getManifestFile(self):
        return os.path.join(self.getBaseDir(), 'HandlerManifest.json')

    def getEnvironmentFile(self):
        return os.path.join(self.getBaseDir(), 'HandlerEnvironment.json')

    def getLogDir(self):
        return os.path.join(OSUtil.GetExtLogDir(), self.getName(), 
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
        return self.data['handlerManifest']["rebootAfterInstall"]

    def isReportHeartbeat(self):
        if "reportHeartbeat" not in self.data['handlerManifest']:
            return False
        return self.data['handlerManifest']["reportHeartbeat"]

    def isUpdateWithInstall(self):
        if "updateMode" not in self.data['handlerManifest']:
            return False
        if "updateMode" in self.data:
            return self.data['handlerManifest']["updateMode"].lower() == "updatewithinstall"
        return False
