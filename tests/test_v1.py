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
import tests.tools as tools
from tools import *
import uuid
import unittest
import os
import time
import httplib
import azurelinuxagent.logger as logger
import azurelinuxagent.protocol.v1 as v1
from test_version import VersionInfoSample
from test_goalstate import GoalStateSample
from test_hostingenv import HostingEnvSample
from test_sharedconfig import SharedConfigSample
from test_certificates import CertificatesSample, TransportCert
from test_extensionsconfig import ExtensionsConfigSample, ManifestSample

#logger.LoggerInit("/dev/stdout", "/dev/null", verbose=True)
#logger.LoggerInit("/dev/stdout", "/dev/null", verbose=False)

def MockFetchUri(url, headers=None, chkProxy=False):
    content = None
    if "versions" in url:
        content = VersionInfoSample
    elif "goalstate" in url:
        content = GoalStateSample
    elif "hostingenvuri" in url:
        content = HostingEnvSample
    elif "sharedconfiguri" in url:
        content = SharedConfigSample
    elif "certificatesuri" in url:
        content = CertificatesSample
    elif "extensionsconfiguri" in url:
        content = ExtensionsConfigSample
    elif "manifest.xml" in url:
        content = ManifestSample
    else:
        raise Exception("Bad url {0}".format(url))
    return content

def MockFetchManifest(uris):
    return ManifestSample

def MockFetchCache(filePath):
    content = None
    if "Incarnation" in filePath:
        content = 1
    elif "GoalState" in filePath:
        content = GoalStateSample
    elif "HostingEnvironmentConfig" in filePath:
        content = HostingEnvSample
    elif "SharedConfig" in filePath:
        content = SharedConfigSample
    elif "Certificates" in filePath:
        content = CertificatesSample
    elif "TransportCert" in filePath:
        content = TransportCert
    elif "ExtensionsConfig" in filePath:
        content = ExtensionsConfigSample
    elif "manifest" in filePath:
        content = ManifestSample
    else:
        raise Exception("Bad filepath {0}".format(filePath))
    return content

class TestWireClint(unittest.TestCase):

    @Mockup(v1, '_fetchCache', MockFetchCache)
    def testGet(self):
        os.chdir('/tmp')
        client = v1.WireClient("foobar")
        goalState = client.getGoalState()
        self.assertNotEquals(None, goalState)
        hostingEnv = client.getHostingEnv()
        self.assertNotEquals(None, hostingEnv)
        sharedConfig = client.getSharedConfig()
        self.assertNotEquals(None, sharedConfig)
        extensionsConfig = client.getExtensionsConfig()
        self.assertNotEquals(None, extensionsConfig)
   
    
    @Mockup(v1, '_fetchCache', MockFetchCache)
    def testGetHeaderWithCert(self):
        client = v1.WireClient("foobar")
        header = client.getHeaderWithCert()
        self.assertNotEquals(None, header)

    @Mockup(v1.WireClient, 'getHeaderWithCert', MockFunc()) 
    @Mockup(v1, '_fetchUri', MockFetchUri)
    @Mockup(v1.fileutil, 'SetFileContents', MockFunc())
    def testUpdateGoalState(self):
        client = v1.WireClient("foobar")
        client.updateGoalState()
        goalState = client.getGoalState()
        self.assertNotEquals(None, goalState)
        hostingEnv = client.getHostingEnv()
        self.assertNotEquals(None, hostingEnv)
        sharedConfig = client.getSharedConfig()
        self.assertNotEquals(None, sharedConfig)
        extensionsConfig = client.getExtensionsConfig()
        self.assertNotEquals(None, extensionsConfig)

class MockResp(object):
    def __init__(self):
        self.status = httplib.OK

class TestStatusBlob(unittest.TestCase):
    def testToJson(self):
        statusBlob = v1.StatusBlob()
        statusBlob.setAgentStatus("1.0", "Hehe", "Haha")
        statusBlob.setExtensionStatus("Extension", "1.1", 
                                      {"status":"success"})
        self.assertNotEquals(None, statusBlob.toJson())

    @Mockup(v1.restutil, 'HttpPut', MockFunc(retval=MockResp()))
    @Mockup(v1.restutil, 'HttpHead', MockFunc(retval=MockResp()))
    def test_put_page_blob(self):
        statusBlob = v1.StatusBlob()
        data = ['a'] * 100
        statusBlob.putPageBlob("http://foo.bar", data)

if __name__ == '__main__':
    unittest.main()

