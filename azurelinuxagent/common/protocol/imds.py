# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json

import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.exception import HttpError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import DataContract, set_properties

IMDS_ENDPOINT = '169.254.169.254'
APIVERSION = '2017-08-01'
BASE_URI = "http://{0}/metadata/instance/{1}?api-version={2}"


def get_imds_client():
    return ImdsClient()


class ComputeInfo(DataContract):
    def __init__(self,
                 location=None,
                 name=None,
                 offer=None,
                 osType=None,
                 placementGroupId=None,
                 platformFaultDomain=None,
                 placementUpdateDomain=None,
                 publisher=None,
                 resourceGroupName=None,
                 sku=None,
                 subscriptionId=None,
                 tags=None,
                 version=None,
                 vmId=None,
                 vmSize=None):
        self.location = location
        self.name = name
        self.offer = offer
        self.osType = osType
        self.placementGroupId = placementGroupId
        self.platformFaultDomain = platformFaultDomain
        self.platformUpdateDomain = placementUpdateDomain
        self.publisher = publisher
        self.resourceGroupName = resourceGroupName
        self.sku = sku
        self.subscriptionId = subscriptionId
        self.tags = tags
        self.version = version
        self.vmId = vmId
        self.vmSize = vmSize

    @property
    def image_info(self):
        return "{0}:{1}:{2}:{3}".format(self.publisher, self.offer, self.sku, self.version)


class ImdsClient(object):
    def __init__(self, version=APIVERSION):
        self._api_version = version
        self._headers = {
            'User-Agent': restutil.HTTP_USER_AGENT,
            'Metadata': True,
        }
        pass

    @property
    def compute_url(self):
        return BASE_URI.format(IMDS_ENDPOINT, 'compute', self._api_version)

    def get_compute(self):
        """
        Fetch compute information.

        :return: instance of a ComputeInfo
        :rtype: ComputeInfo
        """
        with restutil.http_get(self.compute_url, headers=self._headers) as resp:
            if restutil.request_failed(resp):
                raise HttpError("{0} - GET: {1}".format(resp.status, self.compute_url))

            data = resp.read()
            data = json.loads(ustr(data, encoding="utf-8"))

            compute_info = ComputeInfo()
            set_properties('compute', compute_info, data)

            return compute_info
