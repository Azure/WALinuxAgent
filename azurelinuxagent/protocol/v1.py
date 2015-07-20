# Windows Azure Linux Agent
#
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

import os
import json
import re
import time
import traceback
import httplib
import xml.sax.saxutils as saxutils
import xml.etree.ElementTree as ET
import azurelinuxagent.logger as logger
import azurelinuxagent.utils.restutil as restutil

from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
from azurelinuxagent.utils.textutil import *
from azurelinuxagent.protocol.common import *

VERSION_INFO_URI = "http://{0}/?comp=versions"
GOAL_STATE_URI = "http://{0}/machine/?comp=goalstate"
HEALTH_REPORT_URI = "http://{0}/machine?comp=health"
ROLE_PROP_URI = "http://{0}/machine?comp=roleProperties"
TELEMETRY_URI = "http://{0}/machine?comp=telemetrydata"

WIRE_SERVER_ADDR_FILE_NAME = "WireServer"
INCARNATION_FILE_NAME = "Incarnation"
GOAL_STATE_FILE_NAME = "GoalState.{0}.xml"
HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
SHARED_CONF_FILE_NAME = "SharedConfig.xml"
CERTS_FILE_NAME = "Certificates.xml"
P7M_FILE_NAME = "Certificates.p7m"
PEM_FILE_NAME = "Certificates.pem"
EXT_CONF_FILE_NAME = "ExtensionsConfig.{0}.xml"
MANIFEST_FILE_NAME = "{0}.{1}.manifest.xml"
TRANSPORT_CERT_FILE_NAME = "TransportCert.pem"
TRANSPORT_PRV_FILE_NAME = "TransportPrivate.pem"

PROTOCOL_VERSION = "2012-11-30"

class WireProtocolResourceGone(ProtocolError):
    pass

class WIRE_PROTOCOL(Protocol):

    def __init__(self, endpoint):
        self.client = WireClient(endpoint)

    def initialize(self):
        self.client.check_wire_protocol_version()
        self.client.update_goal_state(forced=True)

    def get_vminfo(self):
        hosting_env = self.client.get_hosting_env()
        vminfo = VMInfo()
        vminfo.subscriptionId = None
        vminfo.vmName = hosting_env.vm_name
        return vminfo

    def get_certs(self):
        certificates = self.client.get_certs()
        return certificates.cert_list

    def get_extensions(self):
        #Update goal state to get latest extensions config
        self.client.update_goal_state()
        ext_conf = self.client.get_ext_conf()
        return ext_conf.ext_list

    def get_extension_pkgs(self, extension):
        goal_state = self.client.get_goal_state()
        man = self.client.get_ext_manifest(extension, goal_state)
        return man.pkg_list

    def get_instance_metadata(self):
        goal_state = self.client.get_goal_state()
        hosting_env = self.client.get_hosting_env()
        metadata = InstanceMetadata()
        metadata.deploymentName = hosting_env.deployment_name
        metadata.roleName = hosting_env.role_name
        metadata.roleInstanceId = goal_state.role_instance_id
        metadata.containerId = goal_state.container_id
        return metadata

    def report_provision_status(self, provisionStatus):
        validata_param("provisionStatus", provisionStatus, ProvisionStatus)

        if provisionStatus.status is not None:
            self.client.report_health(provisionStatus.status,
                                     provisionStatus.subStatus,
                                     provisionStatus.description)
        if provisionStatus.properties.certificateThumbprint is not None:
            thumbprint = provisionStatus.properties.certificateThumbprint
            self.client.report_role_prop(thumbprint)

    def report_status(self, vmStatus):
        validata_param("vmStatus", vmStatus, VMStatus)
        self.client.upload_status_blob(vmStatus)

    def report_event(self, events):
        validata_param("events", events, TelemetryEventList)
        self.client.report_event(events)

def _fetch_cache(local_file):
    if not os.path.isfile(local_file):
        raise ProtocolError("{0} is missing.".format(local_file))
    return fileutil.read_file(local_file)

def _fetch_uri(uri, headers, chk_proxy=False):
    try:
        resp = restutil.http_get(uri, headers, chk_proxy=chk_proxy)
    except restutil.HttpError as e:
        raise ProtocolError(str(e))

    if(resp.status == httplib.GONE):
        raise WireProtocolResourceGone(uri)
    if(resp.status != httplib.OK):
        raise ProtocolError("{0} - {1}".format(resp.status, uri))
    return resp.read()

def _fetchManifest(version_uris):
    for versionUri in version_uris:
        try:
            xml_text = _fetch_uri(versionUri.uri, None, chk_proxy=True)
            return xml_text
        except IOError, e:
            logger.warn("Failed to fetch ExtensionManifest: {0}, {1}", e,
                        versionUri.uri)
    raise ProtocolError("Failed to fetch ExtensionManifest from all sources")

def _build_role_properties(container_id, role_instance_id, thumbprint):
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<RoleProperties>"
            "<Container>"
            "<ContainerId>{0}</ContainerId>"
            "<RoleInstances>"
            "<RoleInstance>"
            "<Id>{1}</Id>"
            "<Properties>"
            "<Property name=\"CertificateThumbprint\" value=\"{2}\" />"
            "</Properties>"
            "</RoleInstance>"
            "</RoleInstances>"
            "</Container>"
            "</RoleProperties>"
            "").format(container_id, role_instance_id, thumbprint)
    return xml

def _buildHealthReport(incarnation, container_id, role_instance_id,
                       status, subStatus, description):
    detail = ''
    if subStatus is not None:
        detail = ("<Details>"
                  "<SubStatus>{0}</SubStatus>"
                  "<Description>{1}</Description>"
                  "</Details>").format(subStatus, description)
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<Health "
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
            " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
            "<GoalStateIncarnation>{0}</GoalStateIncarnation>"
            "<Container>"
            "<ContainerId>{1}</ContainerId>"
            "<RoleInstanceList>"
            "<Role>"
            "<InstanceId>{2}</InstanceId>"
            "<Health>"
            "<State>{3}</State>"
            "{4}"
            "</Health>"
            "</Role>"
            "</RoleInstanceList>"
            "</Container>"
            "</Health>"
            "").format(incarnation,
                       container_id,
                       role_instance_id,
                       status,
                       detail)
    return xml

"""
Convert VMStatus object to status blob format
"""
def guest_agent_status_to_v1(ga_status):
    formatted_msg = {
        'lang' : 'en-US',
        'message' : ga_status.message
    }
    v1_ga_status = {
        'version' : ga_status.agentVersion,
        'status' : ga_status.status,
        'formattedMessage' : formatted_msg
    }
    return v1_ga_status

def extension_substatus_to_v1(sub_status_list):
    status_list = []
    for substatus in sub_status_list:
        status = {
            "name": substatus.name,
            "status": substatus.status,
            "code": substatus.code,
            "formattedMessage":{
                "lang": "en-US",
                "message": substatus.message
            }
        }
        status_list.append(status)
    return status_list

def extension_handler_status_to_v1(handler_status, timestamp):
    if handler_status is None or len(handler_status.extensionStatusList) == 0:
        return
    ext_status = handler_status.extensionStatusList[0]
    sub_status = extension_substatus_to_v1(ext_status.substatusList)
    ext_in_status = {
        "status":{
            "name": ext_status.name,
            "configurationAppliedTime": ext_status.configurationAppliedTime,
            "operation": ext_status.operation,
            "status": ext_status.status,
            "code": ext_status.code,
            "formattedMessage": {
                "lang":"en-US",
                "message": ext_status.message
            }
        },
        "timestampUTC": timestamp
    }

    if len(sub_status) != 0:
        ext_in_status['substatus'] = sub_status

    v1_handler_status = {
        'handlerVersion' : handler_status.handlerVersion,
        'handlerName' : handler_status.handlerName,
        'status' : handler_status.status,
        'runtimeSettingsStatus' : {
            'settingsStatus' : ext_in_status,
            'sequenceNumber' : ext_status.sequenceNumber
        }
    }
    return v1_handler_status


def vm_status_to_v1(vm_status):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    v1_ga_status = guest_agent_status_to_v1(vm_status.vmAgent)
    v1_handler_status_list = []
    for v1_handler_status in vm_status.extensionHandlers:
        handlerAggStatus = extension_handler_status_to_v1(v1_handler_status,
                                                          timestamp)
        v1_handler_status_list.append(handlerAggStatus)

    v1_agg_status = {
        'guestAgentStatus': v1_ga_status,
        'handlerAggregateStatus' : v1_handler_status_list
    }
    v1_vm_status = {
        'version' : '1.0',
        'timestampUTC' : timestamp,
        'aggregateStatus' : v1_agg_status
    }
    return v1_vm_status


class StatusBlob(object):
    def __init__(self, vm_status):
        self.vm_status = vm_status

    def toJson(self):
        report = vm_status_to_v1(self.vm_status)
        return json.dumps(report)

    __storage_version__ = "2014-02-14"

    def upload(self, url):
        logger.info("Upload status blob")
        blob_type = self.get_blob_type(url)

        data = self.toJson()
        if blob_type == "BlockBlob":
            self.put_block_blob(url, data)
        elif blob_type == "PageBlob":
            self.put_page_blob(url, data)
        else:
            raise ProtocolError("Unknown blob type: {0}".format(blob_type))

    def get_blob_type(self, url):
        #Check blob type
        logger.verb("Check blob type.")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        resp = restutil.http_head(url, {
            "x-ms-date" :  timestamp,
            'x-ms-version' : self.__class__.__storage_version__
        })
        if resp is None or resp.status != httplib.OK:
            raise ProtocolError(("Failed to get status blob type: {0}"
                                 "").format(resp.status))

        blob_type = resp.getheader("x-ms-blob-type")
        logger.verb("Blob type={0}".format(blob_type))
        return blob_type

    def put_block_blob(self, url, data):
        logger.verb("Upload block blob")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        resp = restutil.http_put(url, data, {
            "x-ms-date" :  timestamp,
            "x-ms-blob-type" : "BlockBlob",
            "Content-Length": str(len(data)),
            "x-ms-version" : self.__class__.__storage_version__
        })
        if resp is None or resp.status != httplib.CREATED:
            raise ProtocolError(("Failed to upload block blob: {0}"
                                 "").format(resp.status))

    def put_page_blob(self, url, data):
        logger.verb("Replace old page blob")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        #Align to 512 bytes
        page_blob_size = ((len(data) + 511) / 512) * 512
        resp = restutil.http_put(url, "", {
            "x-ms-date" :  timestamp,
            "x-ms-blob-type" : "PageBlob",
            "Content-Length": "0",
            "x-ms-blob-content-length" : str(page_blob_size),
            "x-ms-version" : self.__class__.__storage_version__
        })
        if resp is None or resp.status != httplib.CREATED:
            raise ProtocolError(("Failed to clean up page blob: {0}"
                                 "").format(resp.status))

        if '?' in url < 0:
            url = "{0}?comp=page".format(url)
        else:
            url = "{0}&comp=page".format(url)

        logger.verb("Upload page blob")
        page_max = 4 * 1024 * 1024 #Max page size: 4MB
        start = 0
        end = 0
        while end < len(data):
            end = min(len(data), start + page_max)
            content_size = end - start
            #Align to 512 bytes
            pageEnd = ((end + 511) / 512) * 512
            buf_size = pageEnd - start
            buf = bytearray(buf_size)
            buf[0 : content_size] = data[start : end]
            resp = restutil.http_put(url, buffer(buf), {
                "x-ms-date" :  timestamp,
                "x-ms-range" : "bytes={0}-{1}".format(start, pageEnd - 1),
                "x-ms-page-write" : "update",
                "x-ms-version" : self.__class__.__storage_version__,
                "Content-Length": str(pageEnd - start)
            })
            if resp is None or resp.status != httplib.CREATED:
                raise ProtocolError(("Failed to upload page blob: {0}"
                                     "").format(resp.status))
            start = end

def event_param_to_v1(param):
    param_format = u'<Param Name="{0}" Value={1} T="{2}" />'
    param_type = type(param.value)
    attr_type = ""
    if param_type is int:
        attr_type = u'mt:uint64'
    elif param_type is str:
        attr_type = u'mt:wstr'
    elif str(param_type).count("'unicode'") > 0:
        attr_type = u'mt:wstr'
    elif param_type is bool:
        attr_type = u'mt:bool'
    elif param_type is float:
        attr_type = u'mt:float64'
    return param_format.format(param.name, saxutils.quoteattr(str(param.value)),
                               attr_type)

def event_to_v1(event):
    params = ""
    for param in event.parameters:
        params += event_param_to_v1(param)
    event_str = (u'<Event id="{0}">'
                 u'<![CDATA[{1}]]>'
                 u'</Event>').format(event.eventId, params)
    return event_str

class WireClient(object):
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.goal_state = None
        self.updated = None
        self.hosting_env = None
        self.shared_conf = None
        self.certs = None
        self.ext_conf = None
        self.req_count = 0

    def update_hosting_env(self, goal_state):
        local_file = HOSTING_ENV_FILE_NAME
        xml_text = _fetch_uri(goal_state.hosting_env_uri, self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.hosting_env = HostingEnv(xml_text)

    def update_shared_conf(self, goal_state):
        local_file = SHARED_CONF_FILE_NAME
        xml_text = _fetch_uri(goal_state.shared_conf_uri, self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.shared_conf = SharedConfig(xml_text)

    def update_certs(self, goal_state):
        local_file = CERTS_FILE_NAME
        xml_text = _fetch_uri(goal_state.certs_uri, self.get_header_for_cert())
        fileutil.write_file(local_file, xml_text)
        self.certs = Certificates(xml_text)

    def update_ext_conf(self, goal_state):
        incarnation = goal_state.incarnation
        local_file = EXT_CONF_FILE_NAME.format(incarnation)
        xml_text = _fetch_uri(goal_state.ext_uri,
                            self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.ext_conf = ExtensionsConfig(xml_text)
        for extension in self.ext_conf.ext_list.extensions:
            self.update_ext_manifest(extension, goal_state)

    def update_ext_manifest(self, extension, goal_state):
        local_file = MANIFEST_FILE_NAME.format(extension.name,
                                        goal_state.incarnation)
        xml_text = _fetchManifest(extension.versionUris)
        fileutil.write_file(local_file, xml_text)

    def update_goal_state(self, forced=False, max_retry=3):
        uri = GOAL_STATE_URI.format(self.endpoint)
        xml_text = _fetch_uri(uri, self.get_header())
        goal_state = GoalState(xml_text)

        if not forced:
            last_incarnation = None
            if(os.path.isfile(INCARNATION_FILE_NAME)):
                last_incarnation = fileutil.read_file(INCARNATION_FILE_NAME)
            new_incarnation = goal_state.incarnation
            if last_incarnation is not None and last_incarnation == new_incarnation:
                #Goalstate is not updated.
                return

        #Start updating goalstate, retry on 410
        for retry in range(0, max_retry):
            try:
                self.goal_state = goal_state
                goal_state_file = GOAL_STATE_FILE_NAME.format(goal_state.incarnation)
                fileutil.write_file(goal_state_file, xml_text)
                fileutil.write_file(INCARNATION_FILE_NAME,
                                         goal_state.incarnation)
                self.update_hosting_env(goal_state)
                self.update_shared_conf(goal_state)
                self.update_certs(goal_state)
                self.update_ext_conf(goal_state)
                return
            except WireProtocolResourceGone:
                logger.info("Incarnation is out of date. Update goalstate.")
                xml_text = _fetch_uri(GOAL_STATE_URI, self.get_header())
                goal_state = GoalState(xml_text)

        raise ProtocolError("Exceeded max retry updating goal state")

    def get_goal_state(self):
        if(self.goal_state is None):
            incarnation = _fetch_cache(INCARNATION_FILE_NAME)
            goal_state_file = GOAL_STATE_FILE_NAME.format(incarnation)
            xml_text = _fetch_cache(goal_state_file)
            self.goal_state = GoalState(xml_text)
        return self.goal_state

    def get_hosting_env(self):
        if(self.hosting_env is None):
            xml_text = _fetch_cache(HOSTING_ENV_FILE_NAME)
            self.hosting_env = HostingEnv(xml_text)
        return self.hosting_env

    def get_shared_conf(self):
        if(self.shared_conf is None):
            xml_text = _fetch_cache(SHARED_CONF_FILE_NAME)
            self.shared_conf = SharedConfig(xml_text)
        return self.shared_conf

    def get_certs(self):
        if(self.certs is None):
            xml_text = _fetch_cache(Certificates)
            self.certs = Certificates(xml_text)
        return self.certs

    def get_ext_conf(self):
        if(self.ext_conf is None):
            goal_state = self.get_goal_state()
            local_file = EXT_CONF_FILE_NAME.format(goal_state.incarnation)
            xml_text = _fetch_cache(local_file)
            self.ext_conf = ExtensionsConfig(xml_text)
        return self.ext_conf

    def get_ext_manifest(self, extension, goal_state):
        local_file = MANIFEST_FILE_NAME.format(extension.name,
                                        goal_state.incarnation)
        xml_text = _fetch_cache(local_file)
        return ExtensionManifest(xml_text)

    def check_wire_protocol_version(self):
        uri = VERSION_INFO_URI.format(self.endpoint)
        version_info_xml = _fetch_uri(uri, None)
        version_info = VersionInfo(version_info_xml)

        preferred = version_info.get_preferred()
        if PROTOCOL_VERSION == preferred:
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
        elif PROTOCOL_VERSION in version_info.get_supported():
            logger.info("Wire protocol version:{0}", PROTOCOL_VERSION)
            logger.warn("Server prefered version:{0}", preferred)
        else:
            error = ("Agent supported wire protocol version: {0} was not "
                     "advised by Fabric.").format(PROTOCOL_VERSION)
            raise ProtocolNotFound(error)

    def upload_status_blob(self, vm_status):
        ext_conf = self.get_ext_conf()
        status_blob = StatusBlob(vm_status)
        status_blob.upload(ext_conf.status_upload_blob)

    def report_role_prop(self, thumbprint):
        goal_state = self.get_goal_state()
        role_prop = _build_role_properties(goal_state.container_id,
                                           goal_state.role_instance_id,
                                           thumbprint)
        role_prop_uri = ROLE_PROP_URI.format(self.endpoint)
        ret = restutil.http_post(role_prop_uri,
                                 role_prop,
                                 headers=self.get_header_for_xml_content())


    def report_health(self, status, substatus, description):
        goal_state = self.get_goal_state()
        health_report = _buildHealthReport(goal_state.incarnation,
                                           goal_state.container_id,
                                           goal_state.role_instance_id,
                                           status,
                                           substatus,
                                           description)
        health_report_uri = HEALTH_REPORT_URI.format(self.endpoint)
        headers = self.get_header_for_xml_content()
        resp = restutil.http_post(health_report_uri,
                                  health_report,
                                  headers=headers)
    def prevent_throttling(self):
        self.req_count += 1
        if self.req_count % 3 == 0:
            logger.info("Sleep 15 before sending event to avoid throttling.")
            self.req_count = 0
            time.sleep(15)

    def send_event(self, provider_id, event_str):
        uri = TELEMETRY_URI.format(self.endpoint)
        data_format = (u'<?xml version="1.0"?>'
                       u'<TelemetryData version="1.0">'
                          u'<Provider id="{0}">{1}'
                          u'</Provider>'
                       u'</TelemetryData>')
        data = data_format.format(provider_id, event_str)
        try:
            self.prevent_throttling()
            header = self.get_header_for_xml_content()
            resp = restutil.http_post(uri, data, header)
        except restutil.HttpError as e:
            raise ProtocolError("Failed to send events:{0}".format(e))

        if resp.status != httplib.OK:
            logger.verb(resp.read())
            raise ProtocolError("Failed to send events:{0}".format(resp.status))

    def report_event(self, event_list):
        buf = {}
        #Group events by providerId
        for event in event_list.events:
            if event.providerId not in buf:
                buf[event.providerId] = ""
            event_str = event_to_v1(event)
            if len(event_str) >= 63 * 1024:
                logger.warn("Single event too large: {0}", event_str[300:])
                continue
            if len(buf[event.providerId] + event_str) >= 63 * 1024:
                self.send_event(event.providerId, buf[event.providerId])
                buf[event.providerId] = ""
            buf[event.providerId] = buf[event.providerId] + event_str

        #Send out all events left in buffer.
        for provider_id in buf.keys():
            if len(buf[provider_id]) > 0:
                self.send_event(provider_id, buf[provider_id])

    def get_header(self):
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":PROTOCOL_VERSION
        }

    def get_header_for_xml_content(self):
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":PROTOCOL_VERSION,
            "Content-Type":"text/xml;charset=utf-8"
        }

    def get_header_for_cert(self):
        cert = ""
        content = _fetch_cache(TRANSPORT_CERT_FILE_NAME)
        for line in content.split('\n'):
            if "CERTIFICATE" not in line:
                cert += line.rstrip()
        return {
            "x-ms-agent-name":"WALinuxAgent",
            "x-ms-version":PROTOCOL_VERSION,
            "x-ms-cipher-name": "DES_EDE3_CBC",
            "x-ms-guest-agent-public-x509-cert":cert
        }

class VersionInfo(object):
    def __init__(self, xml_text):
        """
        Query endpoint server for wire protocol version.
        Fail if our desired protocol version is not seen.
        """
        logger.verb("Load Version.xml")
        self.parse(xml_text)

    def parse(self, xml_text):
        xml_doc = ET.fromstring(xml_text.strip())
        self.preferred = find_first_node(xml_doc, ".//Preferred/Version").text
        logger.info("Fabric preferred wire protocol version:{0}", self.preferred)

        self.supported = []
        nodes = find_all_nodes(xml_doc, ".//Supported/Version")
        for node in nodes:
            version = node.text
            logger.verb("Fabric supported wire protocol version:{0}", version)
            self.supported.append(version)

    def get_preferred(self):
        return self.preferred

    def get_supported(self):
        return self.supported


class GoalState(object):

    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("GoalState.xml is None")
        logger.verb("Load GoalState.xml")
        self.incarnation = None
        self.expected_state = None
        self.hosting_env_uri = None
        self.shared_conf_uri = None
        self.certs_uri = None
        self.ext_uri = None
        self.role_instance_id = None
        self.container_id = None
        self.load_balancer_probe_port = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Request configuration data from endpoint server.
        """
        self.xml_text = xml_text
        xml_doc = ET.fromstring(xml_text.strip())
        self.incarnation = (find_first_node(xml_doc, ".//Incarnation")).text
        self.expected_state = (find_first_node(xml_doc, ".//ExpectedState")).text
        self.hosting_env_uri = (find_first_node(xml_doc,
                                            ".//HostingEnvironmentConfig")).text
        self.shared_conf_uri = (find_first_node(xml_doc, ".//SharedConfig")).text
        node = (find_first_node(xml_doc, ".//Certificates"))
        self.certs_uri = node.text if node is not None else None
        self.ext_uri = (find_first_node(xml_doc, ".//ExtensionsConfig")).text
        self.role_instance_id = (find_first_node(xml_doc,
                                             ".//RoleInstance/InstanceId")).text
        self.container_id = (find_first_node(xml_doc,
                                             ".//Container/ContainerId")).text
        self.load_balancer_probe_port = (find_first_node(xml_doc,
                                                    ".//LBProbePorts/Port")).text
        return self


class HostingEnv(object):
    """
    parse Hosting enviromnet config and store in
    HostingEnvironmentConfig.xml
    """
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("HostingEnvironmentConfig.xml is None")
        logger.verb("Load HostingEnvironmentConfig.xml")
        self.vm_name = None
        self.role_name = None
        self.deployment_name = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        parse and create HostingEnvironmentConfig.xml.
        """
        self.xml_text = xml_text
        xml_doc = ET.fromstring(xml_text.strip())
        self.vm_name = find_first_node(xml_doc, ".//Incarnation").attrib["instance"]
        self.role_name = find_first_node(xml_doc, ".//Role").attrib["name"]
        deployment = find_first_node(xml_doc, ".//Deployment")
        self.deployment_name = deployment.attrib["name"]
        return self

class SharedConfig(object):
    """
    parse role endpoint server and goal state config.
    """
    def __init__(self, xml_text):
        logger.verb("Load SharedConfig.xml")
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        parse and write configuration to file SharedConfig.xml.
        """
        #Not used currently
        return self

class Certificates(object):

    """
    Object containing certificates of host and provisioned user.
    """
    def __init__(self, xml_text=None):
        if xml_text is None:
            raise ValueError("Certificates.xml is None")
        logger.verb("Load Certificates.xml")
        self.lib_dir = OSUTIL.get_lib_dir()
        self.openssl_cmd = OSUTIL.get_openssl_cmd()
        self.cert_list = CertList()
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Parse multiple certificates into seperate files.
        """
        xml_doc = ET.fromstring(xml_text.strip())
        data_node = find_first_node(xml_doc, ".//Data")
        if data_node is None:
            return

        p7m = ("MIME-Version:1.0\n"
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(P7M_FILE_NAME, P7M_FILE_NAME, data_node.text)

        fileutil.write_file(os.path.join(self.lib_dir, P7M_FILE_NAME), p7m)
        #decrypt certificates
        cmd = ("{0} cms -decrypt -in {1} -inkey {2} -recip {3}"
               "| {4} pkcs12 -nodes -password pass: -out {5}"
               "").format(self.openssl_cmd, P7M_FILE_NAME, TRANSPORT_PRV_FILE_NAME,
                               TRANSPORT_CERT_FILE_NAME, self.openssl_cmd, PEM_FILE_NAME)
        shellutil.run(cmd)

        #The parsing process use public key to match prv and crt.
        buf = []
        begin_crt = False
        begin_prv = False
        prvs = {}
        thumbprints = {}
        index = 0
        v1_cert_list = []
        with open(PEM_FILE_NAME) as pem:
            for line in pem.readlines():
                buf.append(line)
                if re.match(r'[-]+BEGIN.*KEY[-]+', line):
                    begin_prv = True
                elif re.match(r'[-]+BEGIN.*CERTIFICATE[-]+', line):
                    begin_crt = True
                elif re.match(r'[-]+END.*KEY[-]+', line):
                    tmp_file = self.write_to_tmp_file(index, 'prv', buf)
                    pub = OSUTIL.get_pubkey_from_prv(tmp_file)
                    prvs[pub] = tmp_file
                    buf = []
                    index += 1
                    begin_prv = False
                elif re.match(r'[-]+END.*CERTIFICATE[-]+', line):
                    tmp_file = self.write_to_tmp_file(index, 'crt', buf)
                    pub = OSUTIL.get_pubkey_from_crt(tmp_file)
                    thumbprint = OSUTIL.get_thumbprint_from_crt(tmp_file)
                    thumbprints[pub] = thumbprint
                    #Rename crt with thumbprint as the file name
                    crt = "{0}.crt".format(thumbprint)
                    v1_cert_list.append({
                        "name":None,
                        "thumbprint":thumbprint
                    })
                    os.rename(tmp_file, os.path.join(self.lib_dir, crt))
                    buf = []
                    index += 1
                    begin_crt = False

        #Rename prv key with thumbprint as the file name
        for pubkey in prvs:
            thumbprint = thumbprints[pubkey]
            if thumbprint:
                tmp_file = prvs[pubkey]
                prv = "{0}.prv".format(thumbprint)
                os.rename(tmp_file, os.path.join(self.lib_dir, prv))

        for v1_cert in v1_cert_list:
            cert = Cert()
            set_properties(cert, v1_cert)
            self.cert_list.certificates.append(cert)

    def write_to_tmp_file(self, index, suffix, buf):
        file_name = os.path.join(self.lib_dir, "{0}.{1}".format(index, suffix))
        with open(file_name, 'w') as tmp:
            tmp.writelines(buf)
        return file_name


class ExtensionsConfig(object):
    """
    parse ExtensionsConfig, downloading and unpacking them to /var/lib/waagent.
    Install if <enabled>true</enabled>, remove if it is set to false.
    """

    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ExtensionsConfig is None")
        logger.verb("Load ExtensionsConfig.xml")
        self.ext_list = ExtensionList()
        self.status_upload_blob = None
        self.parse(xml_text)

    def parse(self, xml_text):
        """
        Write configuration to file ExtensionsConfig.xml.
        """
        xml_doc = ET.fromstring(xml_text.strip())
        plugins = find_all_nodes(xml_doc, ".//Plugins/Plugin")
        settings = find_all_nodes(xml_doc, ".//PluginSettings/Plugin")

        for plugin in plugins:
            ext = Extension()
            ext.name = plugin.attrib["name"]
            ext.properties.version = plugin.attrib["version"]
            ext.properties.state = plugin.attrib["state"]

            autoUpgrade = plugin.attrib["autoUpgrade"]
            if autoUpgrade == "true":
                ext.properties.upgradePolicy = "auto"
            else:
                ext.properties.upgradePolicy = "manual"

            location = plugin.attrib["location"]
            failoverLocation = plugin.attrib["failoverlocation"]
            for uri in [location, failoverLocation]:
                versionUri = ExtensionVersionUri()
                versionUri.uri = uri
                ext.versionUris.append(versionUri)

            name = ext.name
            version = ext.properties.version
            pluginSettings = filter(lambda x: x.attrib["name"] == name and x.attrib["version"] == version,
                                    settings)
            if pluginSettings is None or len(pluginSettings) == 0 :
                continue

            runtimeSettings = None
            runtimeSettingsNode = find_first_node(pluginSettings[0],
                                                "runtimeSettings")
            seqNo = runtimeSettingsNode.attrib["seqNo"]
            runtimeSettingsStr = runtimeSettingsNode.text
            try:
                runtimeSettings = json.loads(runtimeSettingsStr)
            except ValueError as e:
                raise ProtocolError("Invalid extension settings")

            for settings in runtimeSettings["runtimeSettings"]:
                hSettings = settings["handlerSettings"]
                extSettings = ExtensionSettings()
                extSettings.sequenceNumber = seqNo
                extSettings.publicSettings = hSettings["publicSettings"]
                extSettings.privateSettings = hSettings["protectedSettings"]
                thumbprint = hSettings["protectedSettingsCertThumbprint"]
                extSettings.certificateThumbprint = thumbprint
                ext.properties.extensions.append(extSettings)

            self.ext_list.extensions.append(ext)
        self.status_upload_blob = (find_first_node(xml_doc,"StatusUploadBlob")).text

class ExtensionManifest(object):
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ExtensionManifest is None")
        logger.verb("Load ExtensionManifest.xml")
        self.pkg_list = ExtensionPackageList()
        self.parse(xml_text)

    def parse(self, xml_text):
        xml_doc = ET.fromstring(xml_text.strip())
        packages = find_all_nodes(xml_doc, ".//Plugin")
        for package in packages:
            version = find_first_node(package, "Version").text
            uris = find_all_nodes(package, "Uris/Uri")
            uris = map(lambda x : x.text, uris)
            package = ExtensionPackage()
            package.version = version
            for uri in uris:
                packageUri = ExtensionPackageUri()
                packageUri.uri = uri
                package.uris.append(packageUri)
            self.pkg_list.versions.append(package)

