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
import unittest
import json
import azurelinuxagent.protocol.v2 as v2

SAMPLE_IDENTITY=u"""{
    "vmName":"foo", 
    "subscriptionId":"bar"
}"""

SAMPLE_CERTS=u"""{
    "certificates":[{
        "name":"foo", 
        "thumbprint":"bar",
        "certificateDataUri":"baz"
    }]
}"""

SAMPLE_EXT_HANDLER=u"""[{
    "name":"foo",
    "properties":{
        "version":"bar",
        "upgradePolicy": "manual",
        "state": "enabled",
        "extensions":[{
            "name":"baz",
            "sequenceNumber":0,
            "publicSettings":{
                "commandToExecute": "echo 123",
                "uris":[]
            }
        }]
    },
    "versionUris":[{
        "uri":"versionUri.foo"
    }]
}]"""

SAMPLE_EXT_HANDLER_PKGS=u"""{
    "versions": [{
        "version":"foo",
        "uris":[{
            "uri":"bar"
        },{
            "uri":"baz"
        }]
    }]
}"""

def mock_get_data(self, url, headers=None):
    data = u"{}"
    if url.count(u"identity") > 0:
        data = SAMPLE_IDENTITY
    elif url.count(u"certificates") > 0:
        data = SAMPLE_CERTS
    elif url.count(u"extensionHandlers") > 0:
        data = SAMPLE_EXT_HANDLER
    elif url.count(u"versionUri") > 0:
        data = SAMPLE_EXT_HANDLER_PKGS
    return json.loads(data)

class TestMetadataProtocol(unittest.TestCase):
    @mock(v2.MetadataProtocol, '_get_data', mock_get_data)
    def test_getters(self):
        protocol = v2.MetadataProtocol()
        vminfo = protocol.get_vminfo()
        self.assertNotEquals(None, vminfo)
        self.assertNotEquals(None, vminfo.vmName)
        self.assertNotEquals(None, vminfo.subscriptionId)

        protocol.get_certs()

        ext_handers = protocol.get_ext_handlers()
        self.assertNotEquals(None, ext_handers)
        self.assertNotEquals(None, ext_handers.extHandlers)
        self.assertNotEquals(0, len(ext_handers.extHandlers))
        
        ext_hander = ext_handers.extHandlers[0] 
        self.assertNotEquals(None, ext_hander)
        self.assertNotEquals(0, len(ext_hander.properties.extensions))

        ext = ext_hander.properties.extensions[0]
        self.assertNotEquals(None, ext)
        self.assertNotEquals(None, ext.publicSettings)
        self.assertEquals("echo 123", ext.publicSettings.get('commandToExecute'))

        packages = protocol.get_ext_handler_pkgs(ext_handers.extHandlers[0])
        self.assertNotEquals(None, packages)
    
    @mock(v2.MetadataProtocol, '_put_data', MockFunc())
    def test_reporters(self):
        protocol = v2.MetadataProtocol()
        protocol.report_provision_status(v2.ProvisionStatus())
        protocol.report_vm_status(v2.VMStatus())
        protocol.report_ext_status("foo", "baz", v2.ExtensionStatus())
        protocol.report_event(v2.TelemetryEventList())

if __name__ == '__main__':
    unittest.main()
