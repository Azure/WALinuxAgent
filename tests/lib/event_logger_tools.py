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
import platform
import azurelinuxagent.common.event as event
from azurelinuxagent.common.version import DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME
import tests.lib.tools as tools
from tests.lib import wire_protocol_data
from tests.lib.mock_wire_protocol import mock_wire_protocol


class EventLoggerTools(object):
    mock_imds_data = {
        'location': 'uswest',
        'subscriptionId': 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',
        'resourceGroupName': 'test-rg',
        'vmId': '99999999-8888-7777-6666-555555555555',
        'image_origin': 2468
    }

    @staticmethod
    def initialize_event_logger(event_dir):
        """
        Initializes the event logger using mock data for the common parameters; the goal state fields are taken
        from wire_protocol_data.DATA_FILE and the IMDS fields from mock_imds_data.
        """
        if not os.path.exists(event_dir):
            os.mkdir(event_dir)
        event.init_event_logger(event_dir)

        mock_imds_info = tools.Mock()
        mock_imds_info.location = EventLoggerTools.mock_imds_data['location']
        mock_imds_info.subscriptionId = EventLoggerTools.mock_imds_data['subscriptionId']
        mock_imds_info.resourceGroupName = EventLoggerTools.mock_imds_data['resourceGroupName']
        mock_imds_info.vmId = EventLoggerTools.mock_imds_data['vmId']
        mock_imds_info.image_origin = EventLoggerTools.mock_imds_data['image_origin']

        mock_imds_client = tools.Mock()
        mock_imds_client.get_compute = tools.Mock(return_value=mock_imds_info)

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as mock_protocol:
            with tools.patch("azurelinuxagent.common.event.get_imds_client", return_value=mock_imds_client):
                event.initialize_event_logger_vminfo_common_parameters_and_protocal(mock_protocol)

    @staticmethod
    def get_expected_os_version():
        """
        Returns the expected value for the OS Version in telemetry events
        """
        return u"{0}:{1}-{2}-{3}:{4}".format(platform.system(), DISTRO_NAME, DISTRO_VERSION, DISTRO_CODE_NAME, platform.release())
