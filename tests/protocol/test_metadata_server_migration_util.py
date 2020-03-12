# Copyright 2020 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import tempfile
import unittest

import azurelinuxagent.common.osutil.default as osutil
import azurelinuxagent.common.protocol.metadata_server_migration_util as migration_util

from azurelinuxagent.common.protocol.metadata_server_migration_util import _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME, \
                                                                           _LEGACY_METADATA_SERVER_P7B_FILE_NAME, \
                                                                           _KNOWN_METADATASERVER_IP
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP
from tests.tools import AgentTestCase, patch, call

class TestMetadataServerMigrationUtil(AgentTestCase):
    def test_ensure_file_removed(self):
        fp = tempfile.NamedTemporaryFile(delete=False)
        path = fp.name
        directory = os.path.dirname(path)
        file_name = os.path.basename(path)
        migration_util._ensure_file_removed(directory, file_name)
        assert not os.path.exists(path)

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('os.getuid')
    def test_reset_firewall_rules_firewall_enabled(self, get_guid, enable_firewall, osutil):
        enable_firewall.return_value = True
        test_uid = 42
        get_guid.return_value = test_uid
        migration_util._reset_firewall_rules(osutil)
        osutil.remove_rules_files.assert_called_once()
        osutil.remove_firewall.assert_called_once_with(dst_ip=_KNOWN_METADATASERVER_IP, uid=test_uid)
        osutil.enable_firewall.assert_called_once_with(dst_ip=KNOWN_WIRESERVER_IP, uid=test_uid)

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil')
    @patch('azurelinuxagent.common.conf.enable_firewall')
    @patch('os.getuid')
    def test_reset_firewall_rules_firewall_disabled(self, get_guid, enable_firewall, osutil):
        enable_firewall.return_value = False
        test_uid = 42
        get_guid.return_value = test_uid
        migration_util._reset_firewall_rules(osutil)
        osutil.remove_rules_files.assert_called_once()
        osutil.remove_firewall.assert_called_once_with(dst_ip=_KNOWN_METADATASERVER_IP, uid=test_uid)
        osutil.enable_firewall.assert_not_called()

    @patch('azurelinuxagent.common.conf.get_lib_dir')
    @patch('azurelinuxagent.common.protocol.metadata_server_migration_util._ensure_file_removed')
    def test_cleanup_metadata_protocol_certificates(self, ensure_file_removed, get_lib_dir):
        dir_val = "foo"
        get_lib_dir.return_value = dir_val
        migration_util._cleanup_metadata_protocol_certificates()
        calls = [call(dir_val, _LEGACY_METADATA_SERVER_TRANSPORT_PRV_FILE_NAME),
                 call(dir_val, _LEGACY_METADATA_SERVER_TRANSPORT_CERT_FILE_NAME),
                 call(dir_val, _LEGACY_METADATA_SERVER_P7B_FILE_NAME)]
        ensure_file_removed.assert_has_calls(calls, any_order=True)

    @patch('azurelinuxagent.common.osutil.default.DefaultOSUtil')
    @patch('azurelinuxagent.common.protocol.metadata_server_migration_util._cleanup_metadata_protocol_certificates')
    @patch('azurelinuxagent.common.protocol.metadata_server_migration_util._reset_firewall_rules')
    def test_cleanup_metadata_server_artifacts(self, reset_firewall_rules, cleanup_certificates, osutil):
        migration_util.cleanup_metadata_server_artifacts(osutil)
        reset_firewall_rules.assert_called_once_with(osutil)
        cleanup_certificates.assert_called_once()

if __name__ == '__main__':
    unittest.main()
