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
from walinuxagent.utils.osutil import CurrOSInfo, CurrOS

class ExtensionHandler(object):
    def __init__(self, config):
        self.config = config

    def process(self):
        extSettings = self.protocol.getExtensions()
        for setting in extSettings:
            ext = LoadExtensionInstance(setting)
            if ext is None:
                ext = ExtensionInstance(setting, setting.getVersion())
            try:
                ext.handle()
            except Exception, e:
                logger.Error("Failed to handle extension: {0}-{1}, {2}", 
                             setting.getName(),
                             setting.getVersion(),
                             e)

def LoadExtensionInstance(setting):
    """
    Return the highest version instance with the same name
    """
    targetName = setting.getName()
    for dirName in os.listdir(CurrOS.GetLibDir()):
        if dirName.startswith(targetName):
            name, version = ParseExtensionDirName(dirName)
            #Here we need to ensure names are exactly the same.
            if name == targetName:
                ext = ExtensionInstance(setting, version)
                return ext
    return None

class ExtensionInstance(object):
    def __init__(self, setting, currVersion , installed=False):
        self.targetVersion = setting.getTargetVersion(currVersion)
        #Create a copy of setting for current version
        self.setting = setting.copy(currVersion)
        self.installed = installed
        self.logger = logger.Logger(logger.DefaultLogger)
        self.logger.addLoggerAppender(logger.AppenderConfig({
            'type' : 'FILE',
            'level' : 'INFO',
            'file_path' : os.path.join(self.setting.getLogDir(), 
                                       "CommandExecution.log")
        }))
 
    def handle(self):
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
                new = ExtensionInstance(self.setting, targetVersion)
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
        if not sel.installed:
            return
        self.disable()
        self.uninstall()

    def upgrade(self):
        man = self.loadManifest()
        old = self
        new = ExtensionInstance(self.setting, targetVersion)
        new.download()

        old.disable()
        new.update()
        old.uninstall()
        if man.getUpdateWithInstall():
            new.install()
        new.enable()

    def download(self):
        uris = self.getPackageUris()
        package = None
        for uri in uris:
            try:
                package = restutil.HttpGet(uri)
                break
            except Exception, e:
                logger.Warn("Unable to download extension from: {0}", uri)
        if package is None:
            raise Exception("Download extension failed")

        #Unpack the package
        packageFile = os.path.join(CurrOS.GetLibDir(),
                                   os.path.basename(uri) + ".zip")
        fileutil.SetFileContents(packageFile, package)
        baseDir = self.setting.getBaseDir()
        zipfile.ZipFile(packageFile).extractall(baseDir)
        
        #Save manifest
        manFile = fileutil.SearchFor(baseDir, 'HandlerManifest.json')
        man = fileutil.GetFileContents(manFile, removeBom=True)
        fileutil.SetFileContents(self.setting.getManifestFile(), man)    

        #Create status and config dir
        statusDir = self.setting.getStatusDir() 
        fileutil.CreateDir(statusDir, 'root', 0700)
        configDir = self.self.getConfigDir()
        fileutil.CreateDir(configDir, 'root', 0700)

    def enable(self):
        man = self.loadManifest()
        self.updateHandlerEnvironment()
        self.launchCommand(man.getEnableCommand())

    def disable(self):
        man = self.loadManifest()
        self.updateHandlerEnvironment()
        self.launchCommand(man.getDisableCommand())

    def install(self):
        man = self.loadManifest()
        self.updateHandlerEnvironment()
        self.launchCommand(man.getInstallCommand())

    def uninstall(self):
        self.loadManifest()
        self.updateHandlerEnvironment()
        self.launchCommand(man.getUninstallCommand())

    def update(self):
        self.loadManifest()
        self.updateHandlerEnvironment()
        self.launchCommand(man.getUpdateCommand())

    def launchCommand(self, cmd):
        baseDir = self.getBaseDir() 
        cmd = os.path.join(baseDir, cmd)
        cmd = "{0} {1}".format(cmd, baseDir)
        try:
            devnull = open(os.devnull, 'w')
            child = subprocess.Popen(cmd, shell=True, cwd=baseDir, stdout=devnull)
            timeout = 300 
            retry = timeout / 5
            while retry > 0 and child.poll == None:
                time.sleep(5)
                retry -= 1
            if retry == 0:
                self.logger.Error("Process exceeded timeout of {0} seconds" 
                                  "Terminating process", timeout)
                os.kill(child.pid, 9)
            ret = child.wait()
            if code == None or code != 0:
                self.logger.Error("Process {0} returned non-zero exit code"
                                  " ({1})", cmd, code)
        except Exception, e:
            self.logger.Error('Exception launching {0}, {1}', cmd, e)
    
    def loadManifest(self):
        manFile = self.setting.getManifestFile()
        return json.loads(fileutil.GetFileContents(manFile))

    
    def updateHandlerEnvironment(self):
        env = [{
            "name" : self.setting.getName(),
            "seqNo" : self.setting.getSeqNo(),
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

    def getName(self):
        return self.data["name"]

    def getSeqNo(self):
        return self.data["seqNo"]

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
        return self.data["installCommand"]

    def getUninstallCommand(self):
        return self.data["uninstallCommand"]

    def getUpdateCommand(self):
        return self.data["updateCommand"]

    def getEnableCommand(self):
        return self.data["enableCommand"]

    def getDisableCommand(self):
        return self.data["disableCommand"]

    def getRebootAfterInstall(self):
        return self.data["rebootAfterInstall"].lower() == "true"

    def getReportHeartbeat(self):
        return self.data["reportHeartbeat"].lower() == "true"

    def getUpdateWithInstall(self):
        if "updateMode" in self.data:
            return self.data["updateMode"].lower() == "updatewithinstall"
        return False
