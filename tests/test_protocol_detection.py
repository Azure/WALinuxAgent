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
import uuid
import unittest
import os
import azureguestagent.protocol as protocol

class TestProtocolDetection(unittest.TestCase):

    def test_detect_endpoint(self):
        if os.path.isfile('/tmp/MockProtocol'):
            os.remove('/tmp/MockProtocol')
        protocols = [MockProtocolDetectionFailure, MockProtocol]
        protocol.DetectDefaultProtocol(protocols)
        self.assertTrue(os.path.isfile('/tmp/MockProtocol'))

    def test_detection_failure(self):
        with self.assertRaises(protocol.ProtocolNotFound):
            protocols = [MockProtocolDetectionFailure]
            protocol.DetectDefaultProtocol(protocols)

class MockProtocol():
    @staticmethod
    def Detect():
        pass

class MockProtocolDetectionFailure():
    @staticmethod
    def Detect():
        raise protocol.ProtocolNotFound("Mock dection failure.")
    
def MockGetLibDir():
    return '/tmp'

protocol.ProtocolV1 = MockProtocol
protocol.ProtocolV2 = MockProtocolDetectionFailure
protocol.CurrOS.GetLibDir = MockGetLibDir

if __name__ == '__main__':
    unittest.main()
