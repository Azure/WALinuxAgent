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
import tests.tools as tools
from tests.tools import *
import uuid
import unittest
import os
import time
from azurelinuxagent.utils.restutil import httpclient
import azurelinuxagent.logger as logger
import azurelinuxagent.protocol.v1 as v1
from tests.test_version import VersionInfoSample
from tests.test_goalstate import goal_state_sample
from tests.test_hostingenv import hosting_env_sample
from tests.test_sharedconfig import shared_config_sample
from tests.test_certificates import certs_sample, transport_cert
from tests.test_extensionsconfig import ext_conf_sample, manifest_sample

def mock_fetch_config(self, url, headers=None, chk_proxy=False):
    content = None
    if "versions" in url:
        content = VersionInfoSample
    elif "goalstate" in url:
        content = goal_state_sample
    elif "hostingenvuri" in url:
        content = hosting_env_sample
    elif "sharedconfiguri" in url:
        content = shared_config_sample
    elif "certificatesuri" in url:
        content = certs_sample
    elif "extensionsconfiguri" in url:
        content = ext_conf_sample
    elif "manifest.xml" in url:
        content = manifest_sample
    else:
        raise Exception("Bad url {0}".format(url))
    return content

def mock_fetch_manifest(self, uris):
    return manifest_sample

def mock_fetch_cache(self, file_path):
    content = None
    if "Incarnation" in file_path:
        content = 1
    elif "GoalState" in file_path:
        content = goal_state_sample
    elif "HostingEnvironmentConfig" in file_path:
        content = hosting_env_sample
    elif "SharedConfig" in file_path:
        content = shared_config_sample
    elif "Certificates" in file_path:
        content = certs_sample
    elif "TransportCert" in file_path:
        content = transport_cert
    elif "ExtensionsConfig" in file_path:
        content = ext_conf_sample
    elif "manifest" in file_path:
        content = manifest_sample
    else:
        raise Exception("Bad filepath {0}".format(file_path))
    return content

data_with_bom = b'\xef\xbb\xbfhehe'

class MockResp(object):
    def __init__(self, status=v1.httpclient.OK, data=None):
        self.status = status
        self.data = data

    def read(self):
        return self.data

def mock_403():
    return MockResp(status = v1.httpclient.FORBIDDEN)

def mock_410():
    return MockResp(status = v1.httpclient.GONE)

def mock_503():
    return MockResp(status = v1.httpclient.SERVICE_UNAVAILABLE)

class TestWireClint(unittest.TestCase):

    @mock(v1.restutil, 'http_get', MockFunc(retval=MockResp(data=data_with_bom)))
    def test_fetch_uri_with_bom(self):
        client = v1.WireClient("http://foo.bar/")
        client.fetch_config("http://foo.bar", None)

    @mock(v1.WireClient, 'fetch_cache', mock_fetch_cache)
    def test_get(self):
        os.chdir('/tmp')
        client = v1.WireClient("foobar")
        goalState = client.get_goal_state()
        self.assertNotEquals(None, goalState)
        hostingEnv = client.get_hosting_env()
        self.assertNotEquals(None, hostingEnv)
        sharedConfig = client.get_shared_conf()
        self.assertNotEquals(None, sharedConfig)
        extensionsConfig = client.get_ext_conf()
        self.assertNotEquals(None, extensionsConfig)
   
    
    @mock(v1.WireClient, 'fetch_cache', mock_fetch_cache)
    def test_get_head_for_cert(self):
        client = v1.WireClient("foobar")
        header = client.get_header_for_cert()
        self.assertNotEquals(None, header)

    @mock(v1.WireClient, 'get_header_for_cert', MockFunc()) 
    @mock(v1.WireClient, 'fetch_config', mock_fetch_config)
    @mock(v1.WireClient, 'fetch_manifest', mock_fetch_manifest)
    @mock(v1.fileutil, 'write_file', MockFunc())
    def test_update_goal_state(self):
        client = v1.WireClient("foobar")
        client.update_goal_state()
        goal_state = client.get_goal_state()
        self.assertNotEquals(None, goal_state)
        hosting_env = client.get_hosting_env()
        self.assertNotEquals(None, hosting_env)
        shared_config = client.get_shared_conf()
        self.assertNotEquals(None, shared_config)
        ext_conf = client.get_ext_conf()
        self.assertNotEquals(None, ext_conf)

    @mock(v1.time, "sleep", MockFunc())
    def test_call_wireserver(self):
        client = v1.WireClient("foobar")
        self.assertRaises(v1.ProtocolError, client.call_wireserver, mock_403)
        self.assertRaises(v1.WireProtocolResourceGone, client.call_wireserver, 
                          mock_410)

    @mock(v1.time, "sleep", MockFunc())
    def test_call_storage_service(self):
        client = v1.WireClient("foobar")
        self.assertRaises(v1.ProtocolError, client.call_storage_service, 
                          mock_503)


class TestStatusBlob(unittest.TestCase):
    def testToJson(self):
        vm_status = v1.VMStatus()
        status_blob = v1.StatusBlob(v1.WireClient("http://foo.bar/"))
        status_blob.set_vm_status(vm_status)
        self.assertNotEquals(None, status_blob.to_json())

    @mock(v1.restutil, 'http_put', MockFunc(retval=MockResp(httpclient.CREATED)))
    @mock(v1.restutil, 'http_head', MockFunc(retval=MockResp(httpclient.OK)))
    def test_put_page_blob(self):
        vm_status = v1.VMStatus()
        status_blob = v1.StatusBlob(v1.WireClient("http://foo.bar/"))
        status_blob.set_vm_status(vm_status)
        data = 'a' * 100
        status_blob.put_page_blob("http://foo.bar", data)

class TestConvert(unittest.TestCase):
    def test_status(self):
        vm_status = v1.VMStatus() 
        handler_status = v1.ExtHandlerStatus(name="foo")

        ext_statuses = {}

        ext_name="bar"
        ext_status = v1.ExtensionStatus()
        handler_status.extensions.append(ext_name)
        ext_statuses[ext_name] = ext_status

        substatus = v1.ExtensionSubStatus()
        ext_status.substatusList.append(substatus)

        vm_status.vmAgent.extensionHandlers.append(handler_status)
        v1_status = v1.vm_status_to_v1(vm_status, ext_statuses)
        print(v1_status)

    def test_param(self):
        param = v1.TelemetryEventParam()
        event = v1.TelemetryEvent()
        event.parameters.append(param)
        
        v1.event_to_v1(event)

if __name__ == '__main__':
    unittest.main()

