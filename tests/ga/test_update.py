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

from tests.tools import *
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.exception import UpdateError
from azurelinuxagent.ga.update import *
from tests.protocol.mockwiredata import *

class TestUpdate(AgentTestCase):
    def test_error_record(self):
        update_handler = get_update_handler()
        update_handler.mk_ga_dir()

        #Save error record
        err = GuestAgentError(version="1.0")
        update_handler.error_record[err.version] = err
        update_handler.save_error_record()
        
        #Load error record
        update_handler = get_update_handler()
        update_handler.load_error_record()
        self.assertNotEquals(None, update_handler.error_record.get("1.0"))
        
        #Mark failure and save again
        err = update_handler.error_record.get("1.0")
        err.mark_failure()
        update_handler.save_error_record()

        #Re-load the error record and check
        update_handler = get_update_handler()
        update_handler.load_error_record()
        self.assertNotEquals(None, update_handler.error_record.get("1.0"))
        err = update_handler.error_record.get("1.0")
        self.assertNotEquals(0, err.failure_count) 
        self.assertNotEquals(0, err.last_failure) 
    
    @patch("time.sleep")
    @patch("azurelinuxagent.common.protocol.wire.CryptUtil")
    @patch("azurelinuxagent.common.utils.restutil.http_get")
    def test_check_update(self, mock_http_get, MockCryptUtil, _):
        update_handler = get_update_handler()

        test_data = WireProtocolData(DATA_FILE)
        mock_http_get.side_effect = test_data.mock_http_get
        MockCryptUtil.side_effect = test_data.mock_crypt_util

        protocol = WireProtocol("foo.bar")
        protocol.detect()
        update_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        
        update_handler.check_for_update()
        self.assertNotEquals(0, update_handler.agents) 

        latest_agent = update_handler.get_latest_agent()
        self.assertNotEquals(None, latest_agent) 
        self.assertEquals("99999.0.0.0", latest_agent.version) 
        #Only should consider versions >= current version
        self.assertFalse("1.0.0" in update_handler.error_record)
    
    def test_run_extension(self):
        update_handler = get_update_handler()
        
        #Create a mock guest agent instance
        test_script = os.path.join(self.tmp_dir, "mock_success")
        pkg = ExtHandlerPackage(version="1.0")
        latest_agent = GuestAgent(pkg, GuestAgentError(version=pkg.version))
        latest_agent.get_agent_bin = Mock(return_value=test_script)
        
        #Create a test script to mock invoking run-extensions success
        fileutil.write_file(test_script, "#!/bin/bash\nexit 0")
        fileutil.chmod(test_script, 0o700)
        update_handler.run_extensions(latest_agent)

        #Create a test script to mock invoking run-extensions failure
        fileutil.write_file(test_script, "#!/bin/bash\nexit 1")
        self.assertRaises(UpdateError, update_handler.run_extensions, 
                          latest_agent)

class TestGuestAgent(AgentTestCase):
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download(self, mock_http_get):
        update_handler = get_update_handler()
        update_handler.mk_ga_dir()

        ga_pkg = load_bin_data("ga/WALinuxAgent-2.1.5.rc0.zip")
        ga_pkg_resp = MagicMock()
        ga_pkg_resp.status = restutil.httpclient.OK
        ga_pkg_resp.read = Mock(return_value=ga_pkg)
        mock_http_get.return_value= ga_pkg_resp
        
        pkg = ExtHandlerPackage(version="2.1.5.rc0")
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg, GuestAgentError(version=pkg.version))
        agent.download()
        self.assertTrue(agent.is_downloaded())

class TestGuestAgentError(AgentTestCase):
    def test_mark_failure(self):
        err = GuestAgentError()

        self.assertFalse(err.is_blacklisted())

        for i in range(0, MAX_FAILURE):
            err.mark_failure()
        
        #Assume agent failed >= MAX_FAILURE, it should be blacklisted
        self.assertTrue(err.is_blacklisted())
        self.assertEqual(MAX_FAILURE, err.failure_count)
        
        #Clear old failure won't clear recent failure
        err.clear_old_failure()
        self.assertTrue(err.is_blacklisted())

        #Unless we set the failure to earlier than (now - RETAIN_INTERVAL)
        err.last_failure -= RETAIN_INTERVAL * 2
        err.clear_old_failure()
        self.assertFalse(err.is_blacklisted())

if __name__ == '__main__':
    unittest.main()
