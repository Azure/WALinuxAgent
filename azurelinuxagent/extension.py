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
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.restutil as restutil
from azurelinuxagent.utils.osutil import CurrOSInfo, CurrOS

class ExtensionHandler(object):
    def __init__(self, config, protocol):
        self.config = config
        self.protocol = protocol

    def process(self):
        extSettings = self.protocol.getExtensions()
        for setting in extSettings:
            ext = LoadExtensionInstance(setting)
            if ext is None:
                ext = ExtensionInstance(setting, setting.getVersion())
            try:
                ext.handle()
            except Exception, e:
                logger.Error("Failed to handle extension: {0}-{1}, {2}, {3}", 
                             setting.getName(),
                             setting.getVersion(),
                             e,
                             traceback.format_exc())

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
    libDir = CurrOS.GetLibDir()
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
        self.targetVersion = setting.getTargetVersion(currVersion)
        #Create a copy of setting for current version
        self.setting = setting.copy(currVersion)
        self.installed = installed
        fileutil.CreateDir(self.setting.getLogDir(), mode=0644)
        self.logger = logger.Logger(logger.DefaultLogger)
        self.logger.addLoggerAppender(logger.AppenderConfig({
            'type' : 'FILE',
            'level' : 'INFO',
            'file_path' : os.path.join(self.setting.getLogDir(), 
                                       "CommandExecution.log")
        }))
 
    def handle(self):
        self.logger.info("Process extension:{0} {1}", 
                    self.setting.getName(),
                    self.setting.getVersion())
        state = self.setting.getState()
        if state == 'enabled':
            self.handleEnable()
        elif state == 'disabled':
            self.handleDisable()
        elif state == 'uninstall':
            self.handleUninstall()

    def handleEnable(self):
        if self.installed:
            if self.targetVersion > self.setting.getVersion():
                self.upgrade()        
            else:
                self.enable()
        else:
            if self.targetVersion > self.setting.getVersion():
                #This will happen when auto upgrade policy is enabled
                new = ExtensionInstance(self.setting, self.targetVersion)
                new.download()
                new.enable()
            else:
                self.download()
                self.enable()

    def handleDisable(self, setting):
        if not self.installed:
            return
        self.disable()

    def handleUninstall(self, setting):
        if not self.installed:
            return
        self.disable()
        self.uninstall()

    def upgrade(self):
        old = self
        new = ExtensionInstance(self.setting, self.targetVersion)
        new.download()

        old.disable()
        new.update()
        old.uninstall()
        if man.getUpdateWithInstall():
            new.install()
        new.enable()

    def download(self):
        uris = self.setting.getPackageUris()
        package = None
        for uri in uris:
            try:
                resp = restutil.HttpGet(uri)
                if resp is not None:
                    package = resp.read()
                    break
            except Exception, e:
                self.logger.warn("Unable to download extension from: {0}", uri)
        if package is None:
            raise Exception("Download extension failed")

        #Unpack the package
        packageFile = os.path.join(CurrOS.GetLibDir(),
                                   os.path.basename(uri) + ".zip")
        fileutil.SetFileContents(packageFile, bytearray(package))
        baseDir = self.setting.getBaseDir()
        zipfile.ZipFile(packageFile).extractall(baseDir)
        
        #Save HandlerManifest.json
        manFile = fileutil.SearchForFile(baseDir, 'HandlerManifest.json')
        man = fileutil.GetFileContents(manFile, removeBom=True)
        fileutil.SetFileContents(self.setting.getManifestFile(), man)    

        #Create status and config dir
        statusDir = self.setting.getStatusDir() 
        fileutil.CreateDir(statusDir, mode=0700)
        configDir = self.setting.getConfigDir()
        fileutil.CreateDir(configDir, mode=0700)

        #Save HandlerEnvironment.json
        self.createHandlerEnvironment()

    def enable(self):
        man = self.loadManifest()
        self.updateSetting()
        self.launchCommand(man.getEnableCommand())
        fileutil.SetFileContents(self.setting.getHandlerStateFile(),
                                 "Enabled")

    def disable(self):
        man = self.loadManifest()
        self.updateSetting()
        self.launchCommand(man.getDisableCommand())
        fileutil.SetFileContents(self.setting.getHandlerStateFile(),
                                 "Disabled")

    def install(self):
        man = self.loadManifest()
        self.updateSetting()
        self.launchCommand(man.getInstallCommand())
        fileutil.SetFileContents(self.setting.getHandlerStateFile(),
                                 "Installed")

    def uninstall(self):
        self.loadManifest()
        self.updateSetting()
        self.launchCommand(man.getUninstallCommand())
        fileutil.SetFileContents(self.setting.getHandlerStateFile(),
                                 "Uninstalled")

    def update(self):
        self.loadManifest()
        self.updateSetting()
        self.launchCommand(man.getUpdateCommand())
        fileutil.SetFileContents(self.setting.getHandlerStateFile(),
                                 "Installed")

    def launchCommand(self, cmd):
        baseDir = self.setting.getBaseDir() 
        cmd = os.path.join(baseDir, cmd)
        cmd = "{0} {1}".format(cmd, baseDir)
        fileutil.ChangeTreeMod(baseDir, 0700)
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(cmd, shell=True, cwd=baseDir, stdout=devnull)
            timeout = 300 
            retry = timeout / 5
            while retry > 0 and child.poll == None:
                time.sleep(5)
                retry -= 1
            if retry == 0:
                self.logger.error("Process exceeded timeout of {0} seconds" 
                                  "Terminating process", timeout)
                os.kill(child.pid, 9)
            ret = child.wait()
            if ret == None or ret != 0:
                self.logger.error("Process {0} returned non-zero exit code"
                                  " ({1})", cmd, ret)
        except Exception, e:
            self.logger.error('Exception launching {0}, {1}', cmd, e)
            raise e
    
    def loadManifest(self):
        manFile = self.setting.getManifestFile()
        data = json.loads(fileutil.GetFileContents(manFile))
        if data is not None and len(data) > 0:
            return HandlerManifest(data[0])
        raise Exception('Failed to load manifest file.')

    def updateSetting(self):
        #TODO clear old .settings file
        fileutil.SetFileContents(self.setting.getSettingsFile(),
                                 json.dumps(self.setting.getSettings()))

    def createHandlerEnvironment(self):
        env = [{
            "version" : self.setting.getVersion(),
            "handlerEnvironment" : {
                "logFolder" : self.setting.getLogDir(),
                "configFolder" : self.setting.getConfigDir(),
                "statusFolder" : self.setting.getStatusDir(),
                "heartbeatFile" : self.setting.getHeartbeatFile()
            }
        }]
        fileutil.SetFileContents(self.setting.getEnvironmentFile(),
                                 json.dumps(env))
 
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

    def getRebootAfterInstall(self):
        return self.data['handlerManifest']["rebootAfterInstall"].lower() == "true"

    def getReportHeartbeat(self):
        return self.data['handlerManifest']["reportHeartbeat"].lower() == "true"

    def getUpdateWithInstall(self):
        if "updateMode" in self.data:
            return self.data['handlerManifest']["updateMode"].lower() == "updatewithinstall"
        return False
