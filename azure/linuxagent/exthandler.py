class ExtensionInfo():

    def getName(self):
        pass

    def getAddr(self):
        pass

    def getVersion(self):
        pass

class Extension():

    def enable(self):
        pass

    def disable(self):
        pass

    def uninstall(self):
        pass

    def setState(self):
        pass

    def launchCmd(self):
        pass

    def download(self):
        pass

class ExtensionState()
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionEnabled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionDisabled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
        pass

class ExtensionNotInstalled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):

class ExtensionInstalled(ExtensionState):
    
    def handleEnable(self, extension):
        pass

    def handleDisable(self, extension):
        pass

    def handleUninstall(self, extension):
