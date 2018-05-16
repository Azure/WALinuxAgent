# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json

from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.protocol.imds import ComputeInfo, ImdsClient
from azurelinuxagent.common.protocol.restapi import set_properties
from azurelinuxagent.common.utils import restutil
from tests.ga.test_update import ResponseMock
from tests.tools import *


class TestImds(AgentTestCase):
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get(self, mock_http_get):
        mock_http_get().__enter__.return_value = ResponseMock(response='''{
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
        mock_http_get().__exit__.return_value = None

        test_subject = ImdsClient()
        test_subject.get_compute()

        self.assertEqual(3, mock_http_get.call_count)
        positional_args, kw_args = mock_http_get.call_args

        self.assertEqual('http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01', positional_args[0])
        self.assertTrue('User-Agent' in kw_args['headers'])
        self.assertTrue('Metadata' in kw_args['headers'])
        self.assertEqual(True, kw_args['headers']['Metadata'])

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_bad_request(self, mock_http_get):
        mock_http_get().__enter__.return_value = ResponseMock(status=restutil.httpclient.BAD_REQUEST)
        mock_http_get().__exit__.return_value = None

        test_subject = ImdsClient()
        self.assertRaises(HttpError, test_subject.get_compute)

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_get_empty_response(self, mock_http_get):
        mock_http_get().__enter__.return_value = ResponseMock(response=''.encode('utf-8'))
        mock_http_get().__exit__.return_value = None

        test_subject = ImdsClient()
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
        "vmSize": "Standard_D1_v2"
        }'''

        data = json.loads(s, encoding='utf-8')

        compute_info = ComputeInfo()
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

        self.assertEqual('UnitPublisher:UnitOffer:UnitSku:UnitVersion', compute_info.image_info)

