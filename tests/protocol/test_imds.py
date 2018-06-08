# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json

import azurelinuxagent.common.protocol.imds as imds

from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import set_properties
from azurelinuxagent.common.utils import restutil
from tests.ga.test_update import ResponseMock
from tests.tools import *


class TestImds(AgentTestCase):
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get(self, mock_http_get):
        mock_http_get.return_value = ResponseMock(response='''{
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

        test_subject = imds.ImdsClient()
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

        test_subject = imds.ImdsClient()
        self.assertRaises(HttpError, test_subject.get_compute)

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_empty_response(self, mock_http_get):
        mock_http_get.return_value = ResponseMock(response=''.encode('utf-8'))

        test_subject = imds.ImdsClient()
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

        data = json.loads(s, encoding='utf-8')

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

        data = json.loads(s, encoding='utf-8')
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
                                expected_response='[HTTP Failed] [500: reason] error response')

        # 429 response
        self._assert_validation(http_status_code=429,
                                http_response='server busy',
                                expected_valid=False,
                                expected_response='[HTTP Failed] [429: reason] server busy')

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
        self._assert_field('compute', 'name')
        self._assert_field('compute', 'location')
        self._assert_field('compute', 'vmSize')
        self._assert_field('compute', 'subscriptionId')
        self._assert_field('compute')

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
        test_subject = imds.ImdsClient()
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
        self.assertEqual('http://169.254.169.254/metadata/instance/?api-version=2018-02-01',
                         positional_args[0])
        self.assertEqual(expected_valid, validate_response[0])
        self.assertTrue(expected_response in validate_response[1],
                        "Expected: '{0}', Actual: '{1}'"
                        .format(expected_response, validate_response[1]))


if __name__ == '__main__':
    unittest.main()
