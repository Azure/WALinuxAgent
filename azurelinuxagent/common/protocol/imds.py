# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
import json
import re
from collections import namedtuple

import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.exception import HttpError, ResourceGoneError
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.datacontract import DataContract, set_properties
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion

IMDS_ENDPOINT = '169.254.169.254'
APIVERSION = '2018-02-01'
BASE_METADATA_URI = "http://{0}/metadata/{1}?api-version={2}"

IMDS_IMAGE_ORIGIN_UNKNOWN = 0
IMDS_IMAGE_ORIGIN_CUSTOM = 1
IMDS_IMAGE_ORIGIN_ENDORSED = 2
IMDS_IMAGE_ORIGIN_PLATFORM = 3

MetadataResult = namedtuple('MetadataResult', ['success', 'service_error', 'response'])
IMDS_RESPONSE_SUCCESS = 0
IMDS_RESPONSE_ERROR = 1
IMDS_CONNECTION_ERROR = 2
IMDS_INTERNAL_SERVER_ERROR = 3


def get_imds_client(wireserver_endpoint):
    return ImdsClient(wireserver_endpoint)


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
            logger.periodic_warn(logger.EVERY_FIFTEEN_MINUTES,
                                 "[PERIODIC] Could not determine the image origin from IMDS: {0}".format(ustr(e)))
            return IMDS_IMAGE_ORIGIN_UNKNOWN


class ImdsClient(object):
    def __init__(self, wireserver_endpoint, version=APIVERSION):
        self._api_version = version
        self._headers = {
            'User-Agent': restutil.HTTP_USER_AGENT,
            'Metadata': True,
        }
        self._health_headers = {
            'User-Agent': restutil.HTTP_USER_AGENT_HEALTH,
            'Metadata': True,
        }
        self._regex_ioerror = re.compile(r".*HTTP Failed. GET http://[^ ]+ -- IOError .*")
        self._regex_throttled = re.compile(r".*HTTP Retry. GET http://[^ ]+ -- Status Code 429 .*")
        self._wireserver_endpoint = wireserver_endpoint

    def _get_metadata_url(self, endpoint, resource_path):
        return BASE_METADATA_URI.format(endpoint, resource_path, self._api_version)

    def _http_get(self, endpoint, resource_path, headers):
        url = self._get_metadata_url(endpoint, resource_path)
        return restutil.http_get(url, headers=headers, use_proxy=False)

    def _get_metadata_from_endpoint(self, endpoint, resource_path, headers):
        """
        Get metadata from one of the IMDS endpoints.

        :param str endpoint: IMDS endpoint to call
        :param str resource_path: path of IMDS resource
        :param bool headers: headers to send in the request
        :return: Tuple<status:int, response:str>
            status: one of the following response status codes: IMDS_RESPONSE_SUCCESS, IMDS_RESPONSE_ERROR,
                    IMDS_CONNECTION_ERROR, IMDS_INTERNAL_SERVER_ERROR
            response: IMDS response on IMDS_RESPONSE_SUCCESS, failure message otherwise
        """
        try:
            resp = self._http_get(endpoint=endpoint, resource_path=resource_path, headers=headers)
        except ResourceGoneError:
            return IMDS_INTERNAL_SERVER_ERROR, "IMDS error in /metadata/{0}: HTTP Failed with Status Code 410: Gone".format(resource_path)
        except HttpError as e:
            msg = str(e)
            if self._regex_throttled.match(msg):
                return IMDS_RESPONSE_ERROR, "IMDS error in /metadata/{0}: Throttled".format(resource_path)
            if self._regex_ioerror.match(msg):
                logger.periodic_warn(logger.EVERY_FIFTEEN_MINUTES,
                                     "[PERIODIC] [IMDS_CONNECTION_ERROR] Unable to connect to IMDS endpoint {0}".format(endpoint))
                return IMDS_CONNECTION_ERROR, "IMDS error in /metadata/{0}: Unable to connect to endpoint".format(resource_path)
            return IMDS_INTERNAL_SERVER_ERROR, "IMDS error in /metadata/{0}: {1}".format(resource_path, msg)

        if resp.status >= 500:
            return IMDS_INTERNAL_SERVER_ERROR, "IMDS error in /metadata/{0}: {1}".format(
                                               resource_path, restutil.read_response_error(resp)) 

        if restutil.request_failed(resp):
            return IMDS_RESPONSE_ERROR, "IMDS error in /metadata/{0}: {1}".format(
                                        resource_path, restutil.read_response_error(resp)) 

        return IMDS_RESPONSE_SUCCESS, resp.read()

    def get_metadata(self, resource_path, is_health):
        """
        Get metadata from IMDS, falling back to Wireserver endpoint if necessary.

        :param str resource_path: path of IMDS resource
        :param bool is_health: True if for health/heartbeat, False otherwise
        :return: instance of MetadataResult
        :rtype: MetadataResult
        """
        headers = self._health_headers if is_health else self._headers
        endpoint = IMDS_ENDPOINT

        status, resp = self._get_metadata_from_endpoint(endpoint, resource_path, headers)
        if status == IMDS_CONNECTION_ERROR:
            endpoint = self._wireserver_endpoint
            status, resp = self._get_metadata_from_endpoint(endpoint, resource_path, headers)

        if status == IMDS_RESPONSE_SUCCESS:
            return MetadataResult(True, False, resp)
        elif status == IMDS_INTERNAL_SERVER_ERROR:
            return MetadataResult(False, True, resp)
        return MetadataResult(False, False, resp)

    def get_compute(self):
        """
        Fetch compute information.

        :return: instance of a ComputeInfo
        :rtype: ComputeInfo
        """

        # ensure we get a 200
        result = self.get_metadata('instance/compute', is_health=False)
        if not result.success:
            raise HttpError(result.response)

        data = json.loads(ustr(result.response, encoding="utf-8"))

        compute_info = ComputeInfo()
        set_properties('compute', compute_info, data)

        return compute_info

    def validate(self):
        """
        Determines whether the metadata instance api returns 200, and the response
        is valid: compute should contain location, name, subscription id, and vm size
        and network should contain mac address and private ip address.
        :return: Tuple<is_healthy:bool, error_response:str>
            is_healthy: False when service returns an error, True on successful
                        response and connection failures.
            error_response: validation failure details to assist with debugging
        """

        # ensure we get a 200
        result = self.get_metadata('instance', is_health=True)
        if not result.success:
            # we should only return False when the service is unhealthy
            return (not result.service_error), result.response

        # ensure the response is valid json
        try:
            json_data = json.loads(ustr(result.response, encoding="utf-8"))
        except Exception as e:
            return False, "JSON parsing failed: {0}".format(ustr(e))

        # ensure all expected fields are present and have a value
        try:
            # TODO: compute fields cannot be verified yet since we need to exclude rdfe vms (#1249)

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
