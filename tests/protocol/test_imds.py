# Microsoft Azure Linux Agent
#
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

import json
import os
import unittest

import azurelinuxagent.common.protocol.imds as imds

from azurelinuxagent.common.datacontract import set_properties
from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.utils import restutil
from tests.ga.test_update import ResponseMock
from tests.tools import AgentTestCase, data_dir, MagicMock, Mock, patch


def get_mock_compute_response():
    return ResponseMock(response='''{
    "location": "westcentralus",
    "name": "unit_test",
    "offer": "UnitOffer",
    "osType": "Linux",
    "placementGroupId": "",
    "platformFaultDomain": "0",
    "platformUpdateDomain": "0",
    "publisher": "UnitPublisher",
    "resourceGroupName": "UnitResourceGroupName",
    "sku": "UnitSku",
    "subscriptionId": "e4402c6c-2804-4a0a-9dee-d61918fc4d28",
    "tags": "Key1:Value1;Key2:Value2",
    "vmId": "f62f23fb-69e2-4df0-a20b-cb5c201a3e7a",
    "version": "UnitVersion",
    "vmSize": "Standard_D1_v2"
    }'''.encode('utf-8'))


class TestImds(AgentTestCase):

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get(self, mock_http_get):
        mock_http_get.return_value = get_mock_compute_response()

        test_subject = imds.ImdsClient(restutil.KNOWN_WIRESERVER_IP)
        test_subject.get_compute()

        self.assertEqual(1, mock_http_get.call_count)
        positional_args, kw_args = mock_http_get.call_args

        self.assertEqual('http://169.254.169.254/metadata/instance/compute?api-version=2018-02-01', positional_args[0])
        self.assertTrue('User-Agent' in kw_args['headers'])
        self.assertTrue('Metadata' in kw_args['headers'])
        self.assertEqual(True, kw_args['headers']['Metadata'])

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_bad_request(self, mock_http_get):
        mock_http_get.return_value = ResponseMock(status=restutil.httpclient.BAD_REQUEST)

        test_subject = imds.ImdsClient(restutil.KNOWN_WIRESERVER_IP)
        self.assertRaises(HttpError, test_subject.get_compute)

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_internal_service_error(self, mock_http_get):
        mock_http_get.return_value = ResponseMock(status=restutil.httpclient.INTERNAL_SERVER_ERROR)

        test_subject = imds.ImdsClient(restutil.KNOWN_WIRESERVER_IP)
        self.assertRaises(HttpError, test_subject.get_compute)

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_empty_response(self, mock_http_get):
        mock_http_get.return_value = ResponseMock(response=''.encode('utf-8'))

        test_subject = imds.ImdsClient(restutil.KNOWN_WIRESERVER_IP)
        self.assertRaises(ValueError, test_subject.get_compute)

    def test_deserialize_ComputeInfo(self):
        s = '''{
        "location": "westcentralus",
        "name": "unit_test",
        "offer": "UnitOffer",
        "osType": "Linux",
        "placementGroupId": "",
        "platformFaultDomain": "0",
        "platformUpdateDomain": "0",
        "publisher": "UnitPublisher",
        "resourceGroupName": "UnitResourceGroupName",
        "sku": "UnitSku",
        "subscriptionId": "e4402c6c-2804-4a0a-9dee-d61918fc4d28",
        "tags": "Key1:Value1;Key2:Value2",
        "vmId": "f62f23fb-69e2-4df0-a20b-cb5c201a3e7a",
        "version": "UnitVersion",
        "vmSize": "Standard_D1_v2",
        "vmScaleSetName": "MyScaleSet",
        "zone": "In"
        }'''

        data = json.loads(s)

        compute_info = imds.ComputeInfo()
        set_properties("compute", compute_info, data)

        self.assertEqual('westcentralus', compute_info.location)
        self.assertEqual('unit_test', compute_info.name)
        self.assertEqual('UnitOffer', compute_info.offer)
        self.assertEqual('Linux', compute_info.osType)
        self.assertEqual('', compute_info.placementGroupId)
        self.assertEqual('0', compute_info.platformFaultDomain)
        self.assertEqual('0', compute_info.platformUpdateDomain)
        self.assertEqual('UnitPublisher', compute_info.publisher)
        self.assertEqual('UnitResourceGroupName', compute_info.resourceGroupName)
        self.assertEqual('UnitSku', compute_info.sku)
        self.assertEqual('e4402c6c-2804-4a0a-9dee-d61918fc4d28', compute_info.subscriptionId)
        self.assertEqual('Key1:Value1;Key2:Value2', compute_info.tags)
        self.assertEqual('f62f23fb-69e2-4df0-a20b-cb5c201a3e7a', compute_info.vmId)
        self.assertEqual('UnitVersion', compute_info.version)
        self.assertEqual('Standard_D1_v2', compute_info.vmSize)
        self.assertEqual('MyScaleSet', compute_info.vmScaleSetName)
        self.assertEqual('In', compute_info.zone)

        self.assertEqual('UnitPublisher:UnitOffer:UnitSku:UnitVersion', compute_info.image_info)

    def test_is_custom_image(self):
        image_origin = self._setup_image_origin_assert("", "", "", "")
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_CUSTOM, image_origin)

    def test_is_endorsed_CentOS(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.5", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.6", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.7", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.8", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.9", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7.0", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7.1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7.4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7-LVM", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS", "7-RAW", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS-HPC", "6.5", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS-HPC", "6.8", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS-HPC", "7.1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS-HPC", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("OpenLogic", "CentOS-HPC", "7.4", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("OpenLogic", "CentOS", "6.1", ""))

    def test_is_endorsed_CoreOS(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("CoreOS", "CoreOS", "stable", "494.4.0"))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("CoreOS", "CoreOS", "stable", "899.17.0"))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("CoreOS", "CoreOS", "stable", "1688.5.3"))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("CoreOS", "CoreOS", "stable", "494.3.0"))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("CoreOS", "CoreOS", "alpha", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("CoreOS", "CoreOS", "beta", ""))

    def test_is_endorsed_Debian(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("credativ", "Debian", "7", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("credativ", "Debian", "8", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("credativ", "Debian", "9", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("credativ", "Debian", "9-DAILY", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("credativ", "Debian", "10-DAILY", ""))

    def test_is_endorsed_Rhel(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "6.7", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "6.8", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "6.9", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7.0", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7.1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7.4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7-LVM", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL", "7-RAW", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-HANA", "7.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-HANA", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-HANA", "7.4", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP", "7.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP", "7.4", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-APPS", "7.2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-APPS", "7.3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("RedHat", "RHEL-SAP-APPS", "7.4", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("RedHat", "RHEL", "6.6", ""))

    def test_is_endorsed_SuSE(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "11-SP4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "11-SP4", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "12-SP1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "12-SP2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "12-SP3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "12-SP4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES", "12-SP5", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "12-SP1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "12-SP2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "12-SP3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "12-SP4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-BYOS", "12-SP5", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-SAP", "12-SP1", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-SAP", "12-SP2", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-SAP", "12-SP3", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-SAP", "12-SP4", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("SuSE", "SLES-SAP", "12-SP5", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("SuSE", "SLES", "11-SP3", ""))

    def test_is_endorsed_UbuntuServer(self):
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.0-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.1-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.2-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.3-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.4-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.5-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.6-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.7-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "14.04.8-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "16.04-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "18.04-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "20.04-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_ENDORSED, self._setup_image_origin_assert("Canonical", "UbuntuServer", "22.04-LTS", ""))

        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("Canonical", "UbuntuServer", "12.04-LTS", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("Canonical", "UbuntuServer", "17.10", ""))
        self.assertEqual(imds.IMDS_IMAGE_ORIGIN_PLATFORM, self._setup_image_origin_assert("Canonical", "UbuntuServer", "18.04-DAILY-LTS", ""))

    @staticmethod
    def _setup_image_origin_assert(publisher, offer, sku, version):
        s = '''{{
            "publisher": "{0}",
            "offer": "{1}",
            "sku": "{2}",
            "version": "{3}"
        }}'''.format(publisher, offer, sku, version)

        data = json.loads(s)
        compute_info = imds.ComputeInfo()
        set_properties("compute", compute_info, data)

        return compute_info.image_origin

    def test_response_validation(self):
        # invalid json or empty response
        self._assert_validation(http_status_code=200,
                                http_response='',
                                expected_valid=False,
                                expected_response='JSON parsing failed')

        self._assert_validation(http_status_code=200,
                                http_response=None,
                                expected_valid=False,
                                expected_response='JSON parsing failed')

        self._assert_validation(http_status_code=200,
                                http_response='{ bad json ',
                                expected_valid=False,
                                expected_response='JSON parsing failed')

        # 500 response
        self._assert_validation(http_status_code=500,
                                http_response='error response',
                                expected_valid=False,
                                expected_response='IMDS error in /metadata/instance: [HTTP Failed] [500: reason] error response')

        # 429 response - throttling does not mean service is unhealthy
        self._assert_validation(http_status_code=429,
                                http_response='server busy',
                                expected_valid=True,
                                expected_response='[HTTP Failed] [429: reason] server busy')

        # 404 response - error responses do not mean service is unhealthy
        self._assert_validation(http_status_code=404,
                                http_response='not found',
                                expected_valid=True,
                                expected_response='[HTTP Failed] [404: reason] not found')

        # valid json
        self._assert_validation(http_status_code=200,
                                http_response=self._imds_response('valid'),
                                expected_valid=True,
                                expected_response='')
        # unicode
        self._assert_validation(http_status_code=200,
                                http_response=self._imds_response('unicode'),
                                expected_valid=True,
                                expected_response='')

    def test_field_validation(self):
        # TODO: compute fields (#1249)

        self._assert_field('network', 'interface', 'ipv4', 'ipAddress', 'privateIpAddress')
        self._assert_field('network', 'interface', 'ipv4', 'ipAddress')
        self._assert_field('network', 'interface', 'ipv4')
        self._assert_field('network', 'interface', 'macAddress')
        self._assert_field('network')

    def _assert_field(self, *fields):
        response = self._imds_response('valid')
        response_obj = json.loads(ustr(response, encoding="utf-8"))

        # assert empty value
        self._update_field(response_obj, fields, '')
        altered_response = json.dumps(response_obj).encode()
        self._assert_validation(http_status_code=200,
                                http_response=altered_response,
                                expected_valid=False,
                                expected_response='Empty field: [{0}]'.format(fields[-1]))

        # assert missing value
        self._update_field(response_obj, fields, None)
        altered_response = json.dumps(response_obj).encode()
        self._assert_validation(http_status_code=200,
                                http_response=altered_response,
                                expected_valid=False,
                                expected_response='Missing field: [{0}]'.format(fields[-1]))

    def _update_field(self, obj, fields, val):
        if isinstance(obj, list):
            self._update_field(obj[0], fields, val)
        else:
            f = fields[0]
            if len(fields) == 1:
                if val is None:
                    del obj[f]
                else:
                    obj[f] = val
            else:
                self._update_field(obj[f], fields[1:], val)

    @staticmethod
    def _imds_response(f):
        path = os.path.join(data_dir, "imds", "{0}.json".format(f))
        with open(path, "rb") as fh:
            return fh.read()

    def _assert_validation(self, http_status_code, http_response, expected_valid, expected_response):
        test_subject = imds.ImdsClient(restutil.KNOWN_WIRESERVER_IP)
        with patch("azurelinuxagent.common.utils.restutil.http_get") as mock_http_get:
            mock_http_get.return_value = ResponseMock(status=http_status_code,
                                                      reason='reason',
                                                      response=http_response)
            validate_response = test_subject.validate()

        self.assertEqual(1, mock_http_get.call_count)
        positional_args, kw_args = mock_http_get.call_args

        self.assertTrue('User-Agent' in kw_args['headers'])
        self.assertEqual(restutil.HTTP_USER_AGENT_HEALTH, kw_args['headers']['User-Agent'])
        self.assertTrue('Metadata' in kw_args['headers'])
        self.assertEqual(True, kw_args['headers']['Metadata'])
        self.assertEqual('http://169.254.169.254/metadata/instance?api-version=2018-02-01',
                         positional_args[0])
        self.assertEqual(expected_valid, validate_response[0])
        self.assertTrue(expected_response in validate_response[1],
                        "Expected: '{0}', Actual: '{1}'"
                        .format(expected_response, validate_response[1]))

    def test_endpoint_fallback(self):
        # http error status codes are tested in test_response_validation, none of which
        # should trigger a fallback. This is confirmed as _assert_validation will count
        # http GET calls and enforces a single GET call (fallback would cause 2) and
        # checks the url called.

        test_subject = imds.ImdsClient("foo.bar")

        # ensure user-agent gets set correctly
        for is_health, expected_useragent in [(False, restutil.HTTP_USER_AGENT), (True, restutil.HTTP_USER_AGENT_HEALTH)]:
            # set a different resource path for health query to make debugging unit test easier
            resource_path = 'something/health' if is_health else 'something'

            for has_primary_ioerror in (False, True):
                # secondary endpoint unreachable
                test_subject._http_get = Mock(side_effect=self._mock_http_get)  # pylint: disable=protected-access
                self._mock_imds_setup(primary_ioerror=has_primary_ioerror, secondary_ioerror=True)
                result = test_subject.get_metadata(resource_path=resource_path, is_health=is_health)
                self.assertFalse(result.success) if has_primary_ioerror else self.assertTrue(result.success)  # pylint: disable=expression-not-assigned
                self.assertFalse(result.service_error)
                if has_primary_ioerror:
                    self.assertEqual('IMDS error in /metadata/{0}: Unable to connect to endpoint'.format(resource_path), result.response)
                else:
                    self.assertEqual('Mock success response', result.response)
                for _, kwargs in test_subject._http_get.call_args_list:  # pylint: disable=protected-access
                    self.assertTrue('User-Agent' in kwargs['headers'])
                    self.assertEqual(expected_useragent, kwargs['headers']['User-Agent'])
                self.assertEqual(2 if has_primary_ioerror else 1, test_subject._http_get.call_count)  # pylint: disable=protected-access

                # IMDS success
                test_subject._http_get = Mock(side_effect=self._mock_http_get)  # pylint: disable=protected-access
                self._mock_imds_setup(primary_ioerror=has_primary_ioerror)
                result = test_subject.get_metadata(resource_path=resource_path, is_health=is_health)
                self.assertTrue(result.success)
                self.assertFalse(result.service_error)
                self.assertEqual('Mock success response', result.response)
                for _, kwargs in test_subject._http_get.call_args_list:  # pylint: disable=protected-access
                    self.assertTrue('User-Agent' in kwargs['headers'])
                    self.assertEqual(expected_useragent, kwargs['headers']['User-Agent'])
                self.assertEqual(2 if has_primary_ioerror else 1, test_subject._http_get.call_count)  # pylint: disable=protected-access

                # IMDS throttled
                test_subject._http_get = Mock(side_effect=self._mock_http_get)  # pylint: disable=protected-access
                self._mock_imds_setup(primary_ioerror=has_primary_ioerror, throttled=True)
                result = test_subject.get_metadata(resource_path=resource_path, is_health=is_health)
                self.assertFalse(result.success)
                self.assertFalse(result.service_error)
                self.assertEqual('IMDS error in /metadata/{0}: Throttled'.format(resource_path), result.response)
                for _, kwargs in test_subject._http_get.call_args_list:  # pylint: disable=protected-access
                    self.assertTrue('User-Agent' in kwargs['headers'])
                    self.assertEqual(expected_useragent, kwargs['headers']['User-Agent'])
                self.assertEqual(2 if has_primary_ioerror else 1, test_subject._http_get.call_count)  # pylint: disable=protected-access

                # IMDS gone error
                test_subject._http_get = Mock(side_effect=self._mock_http_get)  # pylint: disable=protected-access
                self._mock_imds_setup(primary_ioerror=has_primary_ioerror, gone_error=True)
                result = test_subject.get_metadata(resource_path=resource_path, is_health=is_health)
                self.assertFalse(result.success)
                self.assertTrue(result.service_error)
                self.assertEqual('IMDS error in /metadata/{0}: HTTP Failed with Status Code 410: Gone'.format(resource_path), result.response)
                for _, kwargs in test_subject._http_get.call_args_list:  # pylint: disable=protected-access
                    self.assertTrue('User-Agent' in kwargs['headers'])
                    self.assertEqual(expected_useragent, kwargs['headers']['User-Agent'])
                self.assertEqual(2 if has_primary_ioerror else 1, test_subject._http_get.call_count)  # pylint: disable=protected-access

                # IMDS bad request
                test_subject._http_get = Mock(side_effect=self._mock_http_get)  # pylint: disable=protected-access
                self._mock_imds_setup(primary_ioerror=has_primary_ioerror, bad_request=True)
                result = test_subject.get_metadata(resource_path=resource_path, is_health=is_health)
                self.assertFalse(result.success)
                self.assertFalse(result.service_error)
                self.assertEqual('IMDS error in /metadata/{0}: [HTTP Failed] [404: reason] Mock not found'.format(resource_path), result.response)
                for _, kwargs in test_subject._http_get.call_args_list:  # pylint: disable=protected-access
                    self.assertTrue('User-Agent' in kwargs['headers'])
                    self.assertEqual(expected_useragent, kwargs['headers']['User-Agent'])
                self.assertEqual(2 if has_primary_ioerror else 1, test_subject._http_get.call_count)  # pylint: disable=protected-access

    def _mock_imds_setup(self, primary_ioerror=False, secondary_ioerror=False, gone_error=False, throttled=False, bad_request=False):
        self._mock_imds_expect_fallback = primary_ioerror  # pylint: disable=attribute-defined-outside-init
        self._mock_imds_primary_ioerror = primary_ioerror  # pylint: disable=attribute-defined-outside-init
        self._mock_imds_secondary_ioerror = secondary_ioerror  # pylint: disable=attribute-defined-outside-init
        self._mock_imds_gone_error = gone_error  # pylint: disable=attribute-defined-outside-init
        self._mock_imds_throttled = throttled  # pylint: disable=attribute-defined-outside-init
        self._mock_imds_bad_request = bad_request  # pylint: disable=attribute-defined-outside-init

    def _mock_http_get(self, *_, **kwargs):
        if "foo.bar" == kwargs['endpoint'] and not self._mock_imds_expect_fallback:
            raise Exception("Unexpected endpoint called")
        if self._mock_imds_primary_ioerror and "169.254.169.254" == kwargs['endpoint']:
            raise HttpError("[HTTP Failed] GET http://{0}/metadata/{1} -- IOError timed out -- 6 attempts made"
                            .format(kwargs['endpoint'], kwargs['resource_path']))
        if self._mock_imds_secondary_ioerror and "foo.bar" == kwargs['endpoint']:
            raise HttpError("[HTTP Failed] GET http://{0}/metadata/{1} -- IOError timed out -- 6 attempts made"
                            .format(kwargs['endpoint'], kwargs['resource_path']))
        if self._mock_imds_gone_error:
            raise ResourceGoneError("Resource is gone")
        if self._mock_imds_throttled:
            raise HttpError("[HTTP Retry] GET http://{0}/metadata/{1} -- Status Code 429 -- 25 attempts made"
                            .format(kwargs['endpoint'], kwargs['resource_path']))

        resp = MagicMock()
        resp.reason = 'reason'
        if self._mock_imds_bad_request:
            resp.status = httpclient.NOT_FOUND
            resp.read.return_value = 'Mock not found'
        else:
            resp.status = httpclient.OK
            resp.read.return_value = 'Mock success response'
        return resp


if __name__ == '__main__':
    unittest.main()
