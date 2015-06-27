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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import env
from tests.tools import *
import uuid
import unittest
import os
import json
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import OSUtil
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.protocol as prot
import azurelinuxagent.distro.default.extension as ext

extensionData = {
    "name":"TestExt",
    "properties":{
        "version":"2.0",
        "state":"enabled",
        "upgradePolicy":"auto",
        "extensions":[{
            "sequenceNumber": 0,
            "publicSettings": "",
            "protectedSettings": "",
            "certificateThumbprint": ""
        }],
        "versionUris":[{
            "version":"2.1",
            "uris":["http://foo.bar"]
        },{
            "version":"2.0",
            "uris":["http://foo.bar"]
        }]
    }
}
extension = prot.Extension()
prot.set_properties(extension, extensionData)

packageListData={
    "versions": [{
        "version": "2.0",
        "uris":[{
            "uri":"http://foo.bar"
         }]
    },{
        "version": "2.1",
        "uris":[{
            "uri":"http://foo.bar"
         }]
    }]
}
packageList = prot.ExtensionPackageList()
prot.set_properties(packageList, packageListData)

manJson = {
    "handlerManifest":{
        "installCommand": "echo 'install'",
        "uninstallCommand": "echo 'uninstall'",
        "updateCommand": "echo 'update'",
        "enableCommand": "echo 'enable'",
        "disableCommand": "echo 'disable'",
    }
}
man = ext.HandlerManifest(manJson)

def MockLoadManifest(self):
    return man

MockLaunchCommand = MockFunc()
MockSetHandlerStatus = MockFunc()

def MockDownload(self):
    fileutil.CreateDir(self.getBaseDir())
    fileutil.SetFileContents(self.getManifestFile(), json.dumps(manJson))

#logger.LoggerInit("/dev/null", "/dev/stdout")
class TestExtensions(unittest.TestCase):

    def test_load_ext(self):
        libDir = OSUtil.GetLibDir()
        testExt1 = os.path.join(libDir, 'TestExt-1.0')
        testExt2 = os.path.join(libDir, 'TestExt-2.0')
        testExt2 = os.path.join(libDir, 'TestExt-2.1')
        for path in [testExt1, testExt2]:
            if not os.path.isdir(path):
                os.mkdir(path)
        testExt = ext.GetInstalledExtensionVersion('TestExt')
        self.assertEqual('2.1', testExt)

    def test_getters(self):
        testExt = ext.ExtensionInstance(extension, packageList, 
                                        extension.properties.version, False)
        self.assertEqual("/tmp/TestExt-2.0", testExt.getBaseDir())
        self.assertEqual("/tmp/TestExt-2.0/status", testExt.getStatusDir())
        self.assertEqual("/tmp/TestExt-2.0/status/0.status", 
                         testExt.getStatusFile())
        self.assertEqual("/tmp/TestExt-2.0/config/HandlerState", 
                         testExt.getHandlerStateFile())
        self.assertEqual("/tmp/TestExt-2.0/config", testExt.getConfigDir())
        self.assertEqual("/tmp/TestExt-2.0/config/0.settings", 
                         testExt.getSettingsFile())
        self.assertEqual("/tmp/TestExt-2.0/heartbeat.log", 
                         testExt.getHeartbeatFile())
        self.assertEqual("/tmp/TestExt-2.0/HandlerManifest.json", 
                         testExt.getManifestFile())
        self.assertEqual("/tmp/TestExt-2.0/HandlerEnvironment.json", 
                         testExt.getEnvironmentFile())
        self.assertEqual("/tmp/log/TestExt/2.0", testExt.getLogDir())

        testExt = ext.ExtensionInstance(extension, packageList, "2.1", False)
        self.assertEqual("/tmp/TestExt-2.1", testExt.getBaseDir())
        self.assertEqual("2.1", testExt.getTargetVersion())
   
    @Mockup(ext.ExtensionInstance, 'loadManifest', MockLoadManifest)
    @Mockup(ext.ExtensionInstance, 'launchCommand', MockLaunchCommand)
    @Mockup(ext.ExtensionInstance, 'setHandlerStatus', MockSetHandlerStatus)
    def test_handle_uninstall(self):
        MockLaunchCommand.args = None
        MockSetHandlerStatus.args = None
        testExt = ext.ExtensionInstance(extension, packageList, 
                                        extension.properties.version, False)
        testExt.handleUninstall()
        self.assertEqual(None, MockLaunchCommand.args)
        self.assertEqual(None, MockSetHandlerStatus.args)
        self.assertEqual(None, testExt.getCurrOperation())

        testExt = ext.ExtensionInstance(extension, packageList, 
                                        extension.properties.version, True)
        testExt.handleUninstall()
        self.assertEqual(man.getUninstallCommand(), MockLaunchCommand.args[0])
        self.assertEqual("UnInstall", testExt.getCurrOperation())
        self.assertEqual("NotReady", MockSetHandlerStatus.args[0])

    @Mockup(ext.ExtensionInstance, 'loadManifest', MockLoadManifest)
    @Mockup(ext.ExtensionInstance, 'launchCommand', MockLaunchCommand)
    @Mockup(ext.ExtensionInstance, 'download', MockDownload)
    @Mockup(ext.ExtensionInstance, 'getHandlerStatus', MockFunc(retval="enabled"))
    @Mockup(ext.ExtensionInstance, 'setHandlerStatus', MockSetHandlerStatus)
    def test_handle(self):
        #Test enable
        testExt = ext.ExtensionInstance(extension, packageList, 
                                        extension.properties.version, False)
        testExt.initLog()
        self.assertEqual(1, len(testExt.logger.appenders) - len(logger.DefaultLogger.appenders))
        testExt.handle()
        
        #Test upgrade 
        testExt = ext.ExtensionInstance(extension, packageList, 
                                        extension.properties.version, False)
        testExt.initLog()
        self.assertEqual(1, len(testExt.logger.appenders) - len(logger.DefaultLogger.appenders))
        testExt.handle()

    def test_status_convert(self):
        extStatus = json.loads('[{"status": {"status": "success", "formattedMessage": {"lang": "en-US", "message": "Script is finished"}, "operation": "Enable", "code": "0", "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"}, "version": "1.0", "timestampUTC": "2015-06-27T08:34:50Z"}]')
        ext.extension_status_to_v2(extStatus[0], 0)


if __name__ == '__main__':
    unittest.main()
