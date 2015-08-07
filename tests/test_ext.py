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

import tests.env
from tests.tools import *
import uuid
import unittest
import os
import json
import azurelinuxagent.logger as logger
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.protocol as prot
import azurelinuxagent.distro.default.extension as ext

ext_sample_json = {
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
ext_sample = prot.Extension()
prot.set_properties(ext_sample, ext_sample_json)

pkd_list_sample_str={
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
pkg_list_sample = prot.ExtensionPackageList()
prot.set_properties(pkg_list_sample, pkd_list_sample_str)

manifest_sample_str = {
    "handlerManifest":{
        "installCommand": "echo 'install'",
        "uninstallCommand": "echo 'uninstall'",
        "updateCommand": "echo 'update'",
        "enableCommand": "echo 'enable'",
        "disableCommand": "echo 'disable'",
    }
}
manifest_sample = ext.HandlerManifest(manifest_sample_str)

def mock_load_manifest(self):
    return manifest_sample

mock_launch_command = MockFunc()
mock_set_handler_status = MockFunc()

def mock_download(self):
    fileutil.mkdir(self.get_base_dir())
    fileutil.write_file(self.get_manifest_file(), json.dumps(manifest_sample_str))

#logger.LoggerInit("/dev/null", "/dev/stdout")
class TestExtensions(unittest.TestCase):

    def test_load_ext(self):
        libDir = OSUTIL.get_lib_dir()
        test_ext1 = os.path.join(libDir, 'TestExt-1.0')
        test_ext2 = os.path.join(libDir, 'TestExt-2.0')
        test_ext2 = os.path.join(libDir, 'TestExt-2.1')
        for path in [test_ext1, test_ext2]:
            if not os.path.isdir(path):
                os.mkdir(path)
        test_ext = ext.get_installed_version('TestExt')
        self.assertEqual('2.1', test_ext)

    def test_getters(self):
        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, 
                                        ext_sample.properties.version, False)
        self.assertEqual("/tmp/TestExt-2.0", test_ext.get_base_dir())
        self.assertEqual("/tmp/TestExt-2.0/status", test_ext.get_status_dir())
        self.assertEqual("/tmp/TestExt-2.0/status/0.status", 
                         test_ext.get_status_file())
        self.assertEqual("/tmp/TestExt-2.0/config/HandlerState", 
                         test_ext.get_handler_state_file())
        self.assertEqual("/tmp/TestExt-2.0/config", test_ext.get_conf_dir())
        self.assertEqual("/tmp/TestExt-2.0/config/0.settings", 
                         test_ext.get_settings_file())
        self.assertEqual("/tmp/TestExt-2.0/heartbeat.log", 
                         test_ext.get_heartbeat_file())
        self.assertEqual("/tmp/TestExt-2.0/HandlerManifest.json", 
                         test_ext.get_manifest_file())
        self.assertEqual("/tmp/TestExt-2.0/HandlerEnvironment.json", 
                         test_ext.get_env_file())
        self.assertEqual("/tmp/log/TestExt/2.0", test_ext.get_log_dir())

        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, "2.1", False)
        self.assertEqual("/tmp/TestExt-2.1", test_ext.get_base_dir())
        self.assertEqual("2.1", test_ext.get_target_version())
   
    @mock(ext.ExtensionInstance, 'load_manifest', mock_load_manifest)
    @mock(ext.ExtensionInstance, 'launch_command', mock_launch_command)
    @mock(ext.ExtensionInstance, 'set_handler_status', mock_set_handler_status)
    def test_handle_uninstall(self):
        mock_launch_command.args = None
        mock_set_handler_status.args = None
        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, 
                                        ext_sample.properties.version, False)
        test_ext.handle_uninstall()
        self.assertEqual(None, mock_launch_command.args)
        self.assertEqual(None, mock_set_handler_status.args)
        self.assertEqual(None, test_ext.get_curr_op())

        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, 
                                        ext_sample.properties.version, True)
        test_ext.handle_uninstall()
        self.assertEqual(manifest_sample.get_uninstall_command(), mock_launch_command.args[0])
        self.assertEqual("UnInstall", test_ext.get_curr_op())
        self.assertEqual("NotReady", mock_set_handler_status.args[0])

    @mock(ext.ExtensionInstance, 'load_manifest', mock_load_manifest)
    @mock(ext.ExtensionInstance, 'launch_command', mock_launch_command)
    @mock(ext.ExtensionInstance, 'download', mock_download)
    @mock(ext.ExtensionInstance, 'get_handler_status', MockFunc(retval="enabled"))
    @mock(ext.ExtensionInstance, 'set_handler_status', mock_set_handler_status)
    def test_handle(self):
        #Test enable
        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, 
                                        ext_sample.properties.version, False)
        test_ext.init_logger()
        self.assertEqual(1, len(test_ext.logger.appenders) - len(logger.DEFAULT_LOGGER.appenders))
        test_ext.handle()
        
        #Test upgrade 
        test_ext = ext.ExtensionInstance(ext_sample, pkg_list_sample, 
                                        ext_sample.properties.version, False)
        test_ext.init_logger()
        self.assertEqual(1, len(test_ext.logger.appenders) - len(logger.DEFAULT_LOGGER.appenders))
        test_ext.handle()

    def test_status_convert(self):
        ext_status = json.loads('[{"status": {"status": "success", "formattedMessage": {"lang": "en-US", "message": "Script is finished"}, "operation": "Enable", "code": "0", "name": "Microsoft.OSTCExtensions.CustomScriptForLinux"}, "version": "1.0", "timestampUTC": "2015-06-27T08:34:50Z"}]')
        ext.ext_status_to_v2(ext_status[0], 0)


if __name__ == '__main__':
    unittest.main()
