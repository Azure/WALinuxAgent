# Copyright 2018 Microsoft Corporation
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

from azurelinuxagent.pa.rdma.rdma import setup_rdma_device, RDMADeviceHandler
from tests.lib.tools import AgentTestCase, Mock, MagicMock, patch


class TestSetupRdmaDevice(AgentTestCase):

    @patch.object(RDMADeviceHandler, 'start')
    def test_setup_rdma_device_with_valid_mac(self, mock_start):
        """When rdmaMacAddress is present, it should be formatted with colons"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig>'
            '<Instance rdmaIPv4Address="10.0.0.1" rdmaMacAddress="00155D33FF1D" />'
            '</SharedConfig>'
        )

        setup_rdma_device("4.1.0", shared_conf)
        self.assertEqual(mock_start.call_count, 1)

    @patch.object(RDMADeviceHandler, 'start')
    def test_setup_rdma_device_with_empty_mac(self, mock_start):
        """When rdmaMacAddress is empty string, the join should be skipped"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig>'
            '<Instance rdmaIPv4Address="10.0.0.1" rdmaMacAddress="" />'
            '</SharedConfig>'
        )

        # Should not raise TypeError
        setup_rdma_device("4.1.0", shared_conf)
        self.assertEqual(mock_start.call_count, 1)

    @patch.object(RDMADeviceHandler, 'start')
    def test_setup_rdma_device_with_missing_mac_attribute(self, mock_start):
        """When rdmaMacAddress attribute is missing, getattrib returns empty string"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig>'
            '<Instance rdmaIPv4Address="10.0.0.1" />'
            '</SharedConfig>'
        )

        # Should not raise TypeError
        setup_rdma_device("4.1.0", shared_conf)
        self.assertEqual(mock_start.call_count, 1)

    def test_setup_rdma_device_with_invalid_xml(self):
        """When XML cannot be parsed, should raise an XML parsing error"""
        shared_conf = Mock()
        shared_conf.xml_text = "not valid xml<<<"

        with self.assertRaises(Exception):
            setup_rdma_device("4.1.0", shared_conf)

    def test_setup_rdma_device_with_no_instance_element(self):
        """When Instance element is missing, should return without error"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig></SharedConfig>'
        )

        # Should not raise, just return early
        setup_rdma_device("4.1.0", shared_conf)

    def test_mac_address_formatting(self):
        """Verify MAC address is correctly formatted with colons"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig>'
            '<Instance rdmaIPv4Address="10.0.0.1" rdmaMacAddress="00155D33FF1D" />'
            '</SharedConfig>'
        )

        with patch('azurelinuxagent.pa.rdma.rdma.RDMADeviceHandler', return_value=MagicMock()) as mock_cls:
            setup_rdma_device("4.1.0", shared_conf)
            # Verify MAC was formatted as 00:15:5D:33:FF:1D
            mock_cls.assert_called_once_with("10.0.0.1", "00:15:5D:33:FF:1D", "4.1.0")

    @patch.object(RDMADeviceHandler, 'start')
    def test_empty_mac_not_formatted(self, _mock_start):
        """Verify empty MAC address is passed through without formatting"""
        shared_conf = Mock()
        shared_conf.xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SharedConfig>'
            '<Instance rdmaIPv4Address="10.0.0.1" rdmaMacAddress="" />'
            '</SharedConfig>'
        )

        with patch('azurelinuxagent.pa.rdma.rdma.RDMADeviceHandler', return_value=MagicMock()) as mock_cls:
            setup_rdma_device("4.1.0", shared_conf)
            # Empty string should be passed through as-is
            mock_cls.assert_called_once_with("10.0.0.1", "", "4.1.0")
