# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json
import re

import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.exception import HttpError
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.protocol.restapi import DataContract, set_properties
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

IMDS_ENDPOINT = '169.254.169.254'
APIVERSION = '2018-02-01'
BASE_URI = "http://{0}/metadata/instance/{1}?api-version={2}"

IMDS_IMAGE_ORIGIN_UNKNOWN = 0
IMDS_IMAGE_ORIGIN_CUSTOM = 1
IMDS_IMAGE_ORIGIN_ENDORSED = 2
IMDS_IMAGE_ORIGIN_PLATFORM = 3


def get_imds_client():
    return ImdsClient()


# A *slightly* future proof list of endorsed distros.
#  -> e.g. I have predicted the future and said that 20.04-LTS will exist
#     and is endored.
#
# See https://docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros for
# more details.
#
# This is not an exhaustive list. This is a best attempt to mark images as
# endorsed or not.  Image publishers do not encode all of the requisite information
# in their publisher, offer, sku, and version to definitively mark something as
# endorsed or not.  This is not perfect, but it is approximately 98% perfect.
ENDORSED_IMAGE_INFO_MATCHER_JSON = """{
    "CANONICAL": {
        "UBUNTUSERVER": {
            "List": [
                "14.04.0-LTS",
                "14.04.1-LTS",
                "14.04.2-LTS",
                "14.04.3-LTS",
                "14.04.4-LTS",
                "14.04.5-LTS",
                "14.04.6-LTS",
                "14.04.7-LTS",
                "14.04.8-LTS",
                
                "16.04-LTS",
                "16.04.0-LTS",
                "18.04-LTS",
                "20.04-LTS",
                "22.04-LTS"
            ]
        }
    },
    "COREOS": {
        "COREOS": {
            "STABLE": { "Minimum": "494.4.0" }
        }
    },
    "CREDATIV": {
        "DEBIAN": { "Minimum": "7" }
    },
    "OPENLOGIC": {
        "CENTOS": {
            "Minimum": "6.3",
            "List": [
                "7-LVM",
                "7-RAW"
            ]
        },
        "CENTOS-HPC": { "Minimum": "6.3" }
    },
    "REDHAT": {
        "RHEL": { 
            "Minimum": "6.7",
            "List": [
                "7-LVM",
                "7-RAW"
            ]
        },
        "RHEL-HANA": { "Minimum": "6.7" },
        "RHEL-SAP": { "Minimum": "6.7" },
        "RHEL-SAP-APPS": { "Minimum": "6.7" },
        "RHEL-SAP-HANA": { "Minimum": "6.7" }
    },
    "SUSE": {
        "SLES": {
            "List": [
                "11-SP4",
                "11-SP5",
                "11-SP6",
                "12-SP1",
                "12-SP2",
                "12-SP3",
                "12-SP4",
                "12-SP5",
                "12-SP6"
            ]
        },
        "SLES-BYOS": {
            "List": [
                "11-SP4",
                "11-SP5",
                "11-SP6",
                "12-SP1",
                "12-SP2",
                "12-SP3",
                "12-SP4",
                "12-SP5",
                "12-SP6"
            ]
        },
        "SLES-SAP": {
            "List": [
                "11-SP4",
                "11-SP5",
                "11-SP6",
                "12-SP1",
                "12-SP2",
                "12-SP3",
                "12-SP4",
                "12-SP5",
                "12-SP6"
            ]
        }
    }
}"""


class ImageInfoMatcher(object):
    def __init__(self, doc):
        self.doc = json.loads(doc)

    def is_match(self, publisher, offer, sku, version):
        def _is_match_walk(doci, keys):
            key = keys.pop(0).upper()
            if key is None:
                return False

            if key not in doci:
                return False

            if 'List' in doci[key] and keys[0] in doci[key]['List']:
                return True

            if 'Match' in doci[key] and re.match(doci[key]['Match'], keys[0]):
                return True

            if 'Minimum' in doci[key]:
                try:
                    return FlexibleVersion(keys[0]) >= FlexibleVersion(doci[key]['Minimum'])
                except ValueError:
                    pass

            return _is_match_walk(doci[key], keys)

        return _is_match_walk(self.doc, [ publisher, offer, sku, version ])


class ComputeInfo(DataContract):
    __matcher = ImageInfoMatcher(ENDORSED_IMAGE_INFO_MATCHER_JSON)

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
                 vmSize=None,
                 vmScaleSetName=None,
                 zone=None):
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
        self.vmScaleSetName = vmScaleSetName
        self.zone = zone


    @property
    def image_info(self):
        return "{0}:{1}:{2}:{3}".format(self.publisher, self.offer, self.sku, self.version)

    @property
    def image_origin(self):
        """
        An integer value describing the origin of the image.

          0 -> unknown
          1 -> custom - user created image
          2 -> endorsed - See https://docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros
          3 -> platform - non-endorsed image that is available in the Azure Marketplace.
        """

        try:
            if self.publisher == "":
                return IMDS_IMAGE_ORIGIN_CUSTOM

            if ComputeInfo.__matcher.is_match(self.publisher, self.offer, self.sku, self.version):
                return IMDS_IMAGE_ORIGIN_ENDORSED
            else:
                return IMDS_IMAGE_ORIGIN_PLATFORM

        except Exception as e:
            logger.warn("Could not determine the image origin from IMDS: {0}", str(e))
            return IMDS_IMAGE_ORIGIN_UNKNOWN


class ImdsClient(object):
    def __init__(self, version=APIVERSION):
        self._api_version = version
        self._headers = {
            'User-Agent': restutil.HTTP_USER_AGENT,
            'Metadata': True,
        }
        self._health_headers = {
            'User-Agent': restutil.HTTP_USER_AGENT_HEALTH,
            'Metadata': True,
        }
        pass

    @property
    def compute_url(self):
        return BASE_URI.format(IMDS_ENDPOINT, 'compute', self._api_version)

    @property
    def instance_url(self):
        return BASE_URI.format(IMDS_ENDPOINT, '', self._api_version)

    def get_compute(self):
        """
        Fetch compute information.

        :return: instance of a ComputeInfo
        :rtype: ComputeInfo
        """

        resp = restutil.http_get(self.compute_url, headers=self._headers)

        if restutil.request_failed(resp):
            raise HttpError("{0} - GET: {1}".format(resp.status, self.compute_url))

        data = resp.read()
        data = json.loads(ustr(data, encoding="utf-8"))

        compute_info = ComputeInfo()
        set_properties('compute', compute_info, data)

        return compute_info

    def validate(self):
        """
        Determines whether the metadata instance api returns 200, and the response
        is valid: compute should contain location, name, subscription id, and vm size
        and network should contain mac address and private ip address.
        :return: Tuple<is_healthy:bool, error_response:str>
            is_healthy: True when validation succeeds, False otherwise
            error_response: validation failure details to assist with debugging
        """

        # ensure we get a 200
        resp = restutil.http_get(self.instance_url, headers=self._health_headers)
        if restutil.request_failed(resp):
            return False, "{0}".format(restutil.read_response_error(resp))

        # ensure the response is valid json
        data = resp.read()
        try:
            json_data = json.loads(ustr(data, encoding="utf-8"))
        except Exception as e:
            return False, "JSON parsing failed: {0}".format(ustr(e))

        # ensure all expected fields are present and have a value
        try:
            self.check_field(json_data, 'compute')
            self.check_field(json_data['compute'], 'location')
            self.check_field(json_data['compute'], 'name')
            self.check_field(json_data['compute'], 'subscriptionId')
            self.check_field(json_data['compute'], 'vmSize')

            self.check_field(json_data, 'network')
            self.check_field(json_data['network'], 'interface')
            self.check_field(json_data['network']['interface'][0], 'macAddress')
            self.check_field(json_data['network']['interface'][0], 'ipv4')
            self.check_field(json_data['network']['interface'][0]['ipv4'], 'ipAddress')
            self.check_field(json_data['network']['interface'][0]['ipv4']['ipAddress'][0], 'privateIpAddress')
        except ValueError as v:
            return False, ustr(v)

        return True, ''

    @staticmethod
    def check_field(dict_obj, field):
        if field not in dict_obj or dict_obj[field] is None:
            raise ValueError('Missing field: [{0}]'.format(field))

        if len(dict_obj[field]) == 0:
            raise ValueError('Empty field: [{0}]'.format(field))
