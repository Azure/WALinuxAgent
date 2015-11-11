# Microsoft Azure Linux Agent
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
import xml.sax.saxutils as saxutils
import xml.etree.ElementTree as ET
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text, httpclient, bytebuffer
import azurelinuxagent.utils.restutil as restutil
from azurelinuxagent.utils.textutil import parse_doc, findall, find, findtext, \
                                           getattrib, gettext, remove_bom
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.utils.shellutil as shellutil
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

class WireProtocol(Protocol):

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

    def get_ext_handlers(self):
        #Update goal state to get latest extensions config
        self.client.update_goal_state()
        ext_conf = self.client.get_ext_conf()
        return ext_conf.ext_handlers

    def get_ext_handler_pkgs(self, ext_handler):
        goal_state = self.client.get_goal_state()
        man = self.client.get_ext_manifest(ext_handler, goal_state)
        return man.pkg_list
   
    def report_provision_status(self, provision_status):
        validata_param("provision_status", provision_status, ProvisionStatus)

        if provision_status.status is not None:
            self.client.report_health(provision_status.status,
                                      provision_status.subStatus,
                                      provision_status.description)
        if provision_status.properties.certificateThumbprint is not None:
            thumbprint = provision_status.properties.certificateThumbprint
            self.client.report_role_prop(thumbprint)

    def report_vm_status(self, vm_status):
        validata_param("vm_status", vm_status, VMStatus)
        self.client.status_blob.set_vm_status(vm_status)
        self.client.upload_status_blob()

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        validata_param("ext_status", ext_status, ExtensionStatus)
        self.client.status_blob.set_ext_status(ext_handler_name, ext_status)

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
        raise ProtocolError(text(e))

    if(resp.status == httpclient.FORBIDDEN):
        logger.info("Sleep to prevent throttling.")
        time.sleep(10)
    
    if(resp.status == httpclient.GONE):
        raise WireProtocolResourceGone(uri)
    if(resp.status != httpclient.OK):
        raise ProtocolError("{0} - {1}".format(resp.status, uri))
    
    data = resp.read()
    if data is None:
        return None
    data = remove_bom(data)
    xml_text = text(data, encoding='utf-8')
    return xml_text

def _fetch_manifest(version_uris):
    for version_uri in version_uris:
        try:
            xml_text = _fetch_uri(version_uri.uri, None, chk_proxy=True)
            return xml_text
        except IOError as e:
            logger.warn("Failed to fetch ExtensionManifest: {0}, {1}", e,
                        version_uri.uri)
    raise ProtocolError("Failed to fetch ExtensionManifest from all sources")

def _build_role_properties(container_id, role_instance_id, thumbprint):
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
           u"<RoleProperties>"
           u"<Container>"
           u"<ContainerId>{0}</ContainerId>"
           u"<RoleInstances>"
           u"<RoleInstance>"
           u"<Id>{1}</Id>"
           u"<Properties>"
           u"<Property name=\"CertificateThumbprint\" value=\"{2}\" />"
           u"</Properties>"
           u"</RoleInstance>"
           u"</RoleInstances>"
           u"</Container>"
           u"</RoleProperties>"
           u"").format(container_id, role_instance_id, thumbprint)
    return xml

def _build_health_report(incarnation, container_id, role_instance_id,
                       status, substatus, description):
    #Escape '&', '<' and '>'
    description = saxutils.escape(text(description))
    detail = u''
    if substatus is not None:
        substatus = saxutils.escape(text(substatus))
        detail = (u"<Details>"
                  u"<SubStatus>{0}</SubStatus>"
                  u"<Description>{1}</Description>"
                  u"</Details>").format(substatus, description)
    xml = (u"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
           u"<Health "
           u"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
           u" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
           u"<GoalStateIncarnation>{0}</GoalStateIncarnation>"
           u"<Container>"
           u"<ContainerId>{1}</ContainerId>"
           u"<RoleInstanceList>"
           u"<Role>"
           u"<InstanceId>{2}</InstanceId>"
           u"<Health>"
           u"<State>{3}</State>"
           u"{4}"
           u"</Health>"
           u"</Role>"
           u"</RoleInstanceList>"
           u"</Container>"
           u"</Health>"
           u"").format(incarnation,
                       container_id,
                       role_instance_id,
                       status,
                       detail)
    return xml

"""
Convert VMStatus object to status blob format
"""
def ga_status_to_v1(ga_status):
    formatted_msg = {
        'lang' : 'en-US',
        'message' : ga_status.message
    }
    v1_ga_status = {
        'version' : ga_status.version,
        'status' : ga_status.status,
        'formattedMessage' : formatted_msg
    }
    return v1_ga_status

def ext_substatus_to_v1(sub_status_list):
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

def ext_status_to_v1(ext_name, ext_status):
    if ext_status is None:
        return None
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    v1_sub_status = ext_substatus_to_v1(ext_status.substatusList)
    v1_ext_status = {
        "status":{
            "name": ext_name,
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
    if len(v1_sub_status) != 0:
        v1_ext_status['substatus'] = v1_sub_status
    return v1_ext_status
    
def ext_handler_status_to_v1(handler_status, ext_statuses, timestamp):
    v1_handler_status = {
        'handlerVersion' : handler_status.version,
        'handlerName' : handler_status.name,
        'status' : handler_status.status,
        "formattedMessage": {
            "lang":"en-US",
            "message": handler_status.message
        },
    }

    if len(handler_status.extensions) > 0:
        #Currently, no more than one extension per handler
        ext_name = handler_status.extensions[0]
        ext_status = ext_statuses.get(ext_name)
        v1_ext_status = ext_status_to_v1(ext_name, ext_status)
        if ext_status is not None and v1_ext_status is not None:
            v1_handler_status["runtimeSettingsStatus"] = {
                'settingsStatus' : v1_ext_status,
                'sequenceNumber' : ext_status.sequenceNumber
            }
    return v1_handler_status

def vm_status_to_v1(vm_status, ext_statuses):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    v1_ga_status = ga_status_to_v1(vm_status.vmAgent)
    v1_handler_status_list = []
    for handler_status in vm_status.vmAgent.extensionHandlers:
        v1_handler_status = ext_handler_status_to_v1(handler_status, 
                                                     ext_statuses, timestamp)
        if v1_handler_status is not None:
            v1_handler_status_list.append(v1_handler_status)

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
    def __init__(self):
        self.vm_status = None
        self.ext_statuses = {}

    def set_vm_status(self, vm_status):
        validata_param("vmAgent", vm_status, VMStatus)
        self.vm_status = vm_status
    
    def set_ext_status(self, ext_handler_name, ext_status):
        validata_param("extensionStatus", ext_status, ExtensionStatus)
        self.ext_statuses[ext_handler_name]= ext_status
        
    def to_json(self):
        report = vm_status_to_v1(self.vm_status, self.ext_statuses)
        return json.dumps(report)

    __storage_version__ = "2014-02-14"

    def upload(self, url):
        #TODO upload extension only if content has changed
        logger.verb("Upload status blob")
        blob_type = self.get_blob_type(url)

        data = self.to_json()
        try:
            if blob_type == "BlockBlob":
                self.put_block_blob(url, data)
            elif blob_type == "PageBlob":
                self.put_page_blob(url, data)
            else:
                raise ProtocolError("Unknown blob type: {0}".format(blob_type))
        except restutil.HttpError as e:
            raise ProtocolError("Failed to upload status blob: {0}".format(e))

    def get_blob_type(self, url):
        #Check blob type
        logger.verb("Check blob type.")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            resp = restutil.http_head(url, {
                "x-ms-date" :  timestamp,
                'x-ms-version' : self.__class__.__storage_version__
            })
        except restutil.HttpError as e:
            raise ProtocolError((u"Failed to get status blob type: {0}"
                                 u"").format(e))
        if resp is None or resp.status != httpclient.OK:
            raise ProtocolError(("Failed to get status blob type: {0}"
                                 "").format(resp.status))

        blob_type = resp.getheader("x-ms-blob-type")
        logger.verb("Blob type={0}".format(blob_type))
        return blob_type

    def put_block_blob(self, url, data):
        logger.verb("Upload block blob")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            resp = restutil.http_put(url, data, {
                "x-ms-date" :  timestamp,
                "x-ms-blob-type" : "BlockBlob",
                "Content-Length": text(len(data)),
                "x-ms-version" : self.__class__.__storage_version__
            })
        except restutil.HttpError as e:
            raise ProtocolError((u"Failed to upload block blob: {0}"
                                 u"").format(e))
        if resp.status != httpclient.CREATED:
            raise ProtocolError(("Failed to upload block blob: {0}"
                                 "").format(resp.status))

    def put_page_blob(self, url, data):
        logger.verb("Replace old page blob")

        #Convert string into bytes
        data=bytearray(data, encoding='utf-8')
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        #Align to 512 bytes
        page_blob_size = int((len(data) + 511) / 512) * 512
        try:
            resp = restutil.http_put(url, "", {
                "x-ms-date" :  timestamp,
                "x-ms-blob-type" : "PageBlob",
                "Content-Length": "0",
                "x-ms-blob-content-length" : text(page_blob_size),
                "x-ms-version" : self.__class__.__storage_version__
            })
        except restutil.HttpError as e:
            raise ProtocolError((u"Failed to clean up page blob: {0}"
                                 u"").format(e))
        if resp.status != httpclient.CREATED:
            raise ProtocolError(("Failed to clean up page blob: {0}"
                                 "").format(resp.status))

        if url.count("?") < 0:
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
            page_end = int((end + 511) / 512) * 512
            buf_size = page_end - start
            buf = bytearray(buf_size)
            buf[0: content_size] = data[start: end]
            try:
                resp = restutil.http_put(url, bytebuffer(buf), {
                    "x-ms-date" :  timestamp,
                    "x-ms-range" : "bytes={0}-{1}".format(start, page_end - 1),
                    "x-ms-page-write" : "update",
                    "x-ms-version" : self.__class__.__storage_version__,
                    "Content-Length": text(page_end - start)
                })
            except restutil.HttpError as e:
                raise ProtocolError((u"Failed to upload page blob: {0}"
                                     u"").format(e))
            if resp is None or resp.status != httpclient.CREATED:
                raise ProtocolError(("Failed to upload page blob: {0}"
                                     "").format(resp.status))
            start = end

def event_param_to_v1(param):
    param_format = '<Param Name="{0}" Value={1} T="{2}" />'
    param_type = type(param.value)
    attr_type = ""
    if param_type is int:
        attr_type = 'mt:uint64'
    elif param_type is str:
        attr_type = 'mt:wstr'
    elif text(param_type).count("'unicode'") > 0:
        attr_type = 'mt:wstr'
    elif param_type is bool:
        attr_type = 'mt:bool'
    elif param_type is float:
        attr_type = 'mt:float64'
    return param_format.format(param.name, saxutils.quoteattr(text(param.value)),
                               attr_type)

def event_to_v1(event):
    params = ""
    for param in event.parameters:
        params += event_param_to_v1(param)
    event_str = ('<Event id="{0}">'
                 '<![CDATA[{1}]]>'
                 '</Event>').format(event.eventId, params)
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
        self.status_blob = StatusBlob()

    def update_hosting_env(self, goal_state):
        if goal_state.hosting_env_uri is None:
            raise ProtocolError("HostingEnvironmentConfig uri is empty")
        local_file = HOSTING_ENV_FILE_NAME
        xml_text = _fetch_uri(goal_state.hosting_env_uri, self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.hosting_env = HostingEnv(xml_text)

    def update_shared_conf(self, goal_state):
        if goal_state.shared_conf_uri is None:
            raise ProtocolError("SharedConfig uri is empty")
        local_file = SHARED_CONF_FILE_NAME
        xml_text = _fetch_uri(goal_state.shared_conf_uri, self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.shared_conf = SharedConfig(xml_text)

    def update_certs(self, goal_state):
        if goal_state.certs_uri is None:
            return
        local_file = CERTS_FILE_NAME
        xml_text = _fetch_uri(goal_state.certs_uri, self.get_header_for_cert())
        fileutil.write_file(local_file, xml_text)
        self.certs = Certificates(xml_text)

    def update_ext_conf(self, goal_state):
        if goal_state.ext_uri is None:
            logger.info("ExtensionsConfig.xml uri is empty")
            self.ext_conf = ExtensionsConfig(None)
            return
        incarnation = goal_state.incarnation
        local_file = EXT_CONF_FILE_NAME.format(incarnation)
        xml_text = _fetch_uri(goal_state.ext_uri,
                            self.get_header())
        fileutil.write_file(local_file, xml_text)
        self.ext_conf = ExtensionsConfig(xml_text)
        for ext_handler in self.ext_conf.ext_handlers.extHandlers:
            self.update_ext_handler_manifest(ext_handler, goal_state)

    def update_ext_handler_manifest(self, ext_handler, goal_state):
        local_file = MANIFEST_FILE_NAME.format(ext_handler.name,
                                               goal_state.incarnation)
        xml_text = _fetch_manifest(ext_handler.versionUris)
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
            if last_incarnation is not None and \
                    last_incarnation == new_incarnation:
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
        if self.certs is None:
            return None
        return self.certs

    def get_ext_conf(self):
        if(self.ext_conf is None):
            goal_state = self.get_goal_state()
            if goal_state.ext_uri is None:
                self.ext_conf = ExtensionsConfig(None)
            else:
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
   
    def upload_status_blob(self):
        ext_conf = self.get_ext_conf()
        if ext_conf.status_upload_blob is not None:
            self.status_blob.upload(ext_conf.status_upload_blob)

    def report_role_prop(self, thumbprint):
        goal_state = self.get_goal_state()
        role_prop = _build_role_properties(goal_state.container_id,
                                           goal_state.role_instance_id,
                                           thumbprint)
        role_prop = role_prop.encode("utf-8")
        role_prop_uri = ROLE_PROP_URI.format(self.endpoint)
        try:
            resp = restutil.http_post(role_prop_uri,
                                      role_prop,
                                      headers=self.get_header_for_xml_content())
        except restutil.HttpError as e:
            raise ProtocolError((u"Failed to send role properties: {0}"
                                 u"").format(e))
        if resp.status != httpclient.ACCEPTED:
            raise ProtocolError((u"Failed to send role properties: {0}"
                                 u", {1}").format(resp.status, resp.read()))

    def report_health(self, status, substatus, description):
        goal_state = self.get_goal_state()
        health_report = _build_health_report(goal_state.incarnation,
                                             goal_state.container_id,
                                             goal_state.role_instance_id,
                                             status,
                                             substatus,
                                             description)
        health_report = health_report.encode("utf-8")
        health_report_uri = HEALTH_REPORT_URI.format(self.endpoint)
        headers = self.get_header_for_xml_content()
        try:
            resp = restutil.http_post(health_report_uri,
                                      health_report,
                                      headers=headers)
        except restutil.HttpError as e:
            raise ProtocolError((u"Failed to send provision status: {0}"
                                 u"").format(e))
        if resp.status != httpclient.OK:
            raise ProtocolError((u"Failed to send provision status: {0}"
                                 u", {1}").format(resp.status, resp.read()))


    def prevent_throttling(self):
        self.req_count += 1
        if self.req_count % 3 == 0:
            logger.info("Sleep 15 before sending event to avoid throttling.")
            self.req_count = 0
            time.sleep(15)

    def send_event(self, provider_id, event_str):
        uri = TELEMETRY_URI.format(self.endpoint)
        data_format = ('<?xml version="1.0"?>'
                       '<TelemetryData version="1.0">'
                          '<Provider id="{0}">{1}'
                          '</Provider>'
                       '</TelemetryData>')
        data = data_format.format(provider_id, event_str)
        try:
            self.prevent_throttling()
            header = self.get_header_for_xml_content()
            resp = restutil.http_post(uri, data, header)
        except restutil.HttpError as e:
            raise ProtocolError("Failed to send events:{0}".format(e))

        if resp.status != httpclient.OK:
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
        for provider_id in list(buf.keys()):
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
        xml_doc = parse_doc(xml_text)
        preferred = find(xml_doc, "Preferred")
        self.preferred = findtext(preferred, "Version")
        logger.info("Fabric preferred wire protocol version:{0}", self.preferred)

        self.supported = []
        supported = find(xml_doc, "Supported")
        supported_version = findall(supported, "Version")
        for node in supported_version:
            version = gettext(node)
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
        xml_doc = parse_doc(xml_text)
        self.incarnation = findtext(xml_doc, "Incarnation")
        self.expected_state = findtext(xml_doc, "ExpectedState")
        self.hosting_env_uri = findtext(xml_doc, "HostingEnvironmentConfig")
        self.shared_conf_uri = findtext(xml_doc, "SharedConfig")
        self.certs_uri = findtext(xml_doc, "Certificates") 
        self.ext_uri = findtext(xml_doc, "ExtensionsConfig")
        role_instance = find(xml_doc, "RoleInstance")
        self.role_instance_id = findtext(role_instance, "InstanceId")
        container = find(xml_doc, "Container")
        self.container_id = findtext(container, "ContainerId")
        lbprobe_ports = find(xml_doc, "LBProbePorts")
        self.load_balancer_probe_port = findtext(lbprobe_ports, "Port")
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
        xml_doc = parse_doc(xml_text)
        incarnation = find(xml_doc, "Incarnation")
        self.vm_name = getattrib(incarnation, "instance")
        role = find(xml_doc, "Role")
        self.role_name = getattrib(role, "name")
        deployment = find(xml_doc, "Deployment")
        self.deployment_name = getattrib(deployment, "name")
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
        xml_doc = parse_doc(xml_text)
        data = findtext(xml_doc, "Data")
        if data is None:
            return

        p7m = ("MIME-Version:1.0\n"
               "Content-Disposition: attachment; filename=\"{0}\"\n"
               "Content-Type: application/x-pkcs7-mime; name=\"{1}\"\n"
               "Content-Transfer-Encoding: base64\n"
               "\n"
               "{2}").format(P7M_FILE_NAME, P7M_FILE_NAME, data)

        fileutil.write_file(os.path.join(self.lib_dir, P7M_FILE_NAME), p7m)
        #decrypt certificates
        cmd = ("{0} cms -decrypt -in {1} -inkey {2} -recip {3}"
               "| {4} pkcs12 -nodes -password pass: -out {5}"
               "").format(self.openssl_cmd, P7M_FILE_NAME, 
                          TRANSPORT_PRV_FILE_NAME, TRANSPORT_CERT_FILE_NAME, 
                          self.openssl_cmd, PEM_FILE_NAME)
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
            set_properties("certs", cert, v1_cert)
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
        logger.verb("Load ExtensionsConfig.xml")
        self.ext_handlers = ExtHandlerList()
        self.status_upload_blob = None
        if xml_text is not None:
            self.parse(xml_text)

    def parse(self, xml_text):
        """
        Write configuration to file ExtensionsConfig.xml.
        """
        xml_doc = parse_doc(xml_text)
        plugins_list = find(xml_doc, "Plugins")
        plugins = findall(plugins_list, "Plugin")
        plugin_settings_list = find(xml_doc, "PluginSettings")
        plugin_settings = findall(plugin_settings_list, "Plugin")

        for plugin in plugins:
            ext_handler = self.parse_plugin(plugin)
            self.ext_handlers.extHandlers.append(ext_handler)
            self.parse_plugin_settings(ext_handler, plugin_settings)

        self.status_upload_blob = findtext(xml_doc, "StatusUploadBlob")

    def parse_plugin(self, plugin):
        ext_handler = ExtHandler()
        ext_handler.name = getattrib(plugin, "name")
        ext_handler.properties.version = getattrib(plugin, "version")
        ext_handler.properties.state = getattrib(plugin, "state")

        auto_upgrade = getattrib(plugin, "autoUpgrade")
        if auto_upgrade is not None and auto_upgrade.lower() == "true":
            ext_handler.properties.upgradePolicy = "auto"
        else:
            ext_handler.properties.upgradePolicy = "manual"

        location = getattrib(plugin, "location")
        failover_location = getattrib(plugin, "failoverlocation")
        for uri in [location, failover_location]:
            version_uri = ExtHandlerVersionUri()
            version_uri.uri = uri
            ext_handler.versionUris.append(version_uri)
        return ext_handler

    def parse_plugin_settings(self, ext_handler, plugin_settings):
        if plugin_settings is None:
            return 

        name = ext_handler.name
        version = ext_handler.properties.version
        settings = [x for x in plugin_settings \
                          if getattrib(x, "name") == name and \
                             getattrib(x ,"version") == version]

        if settings is None or len(settings) == 0:
            return

        runtime_settings = None
        runtime_settings_node = find(settings[0], "RuntimeSettings")
        seqNo = getattrib(runtime_settings_node, "seqNo")
        runtime_settings_str = gettext(runtime_settings_node)
        try:
            runtime_settings = json.loads(runtime_settings_str)
        except ValueError as e:
            logger.error("Invalid extension settings")
            return

        for plugin_settings_list in runtime_settings["runtimeSettings"]:
            handler_settings = plugin_settings_list["handlerSettings"]
            ext = Extension()
            #There is no "extension name" in wire protocol.
            #Put
            ext.name = ext_handler.name
            ext.sequenceNumber = seqNo
            ext.publicSettings = handler_settings.get("publicSettings")
            ext.privateSettings = handler_settings.get("protectedSettings")
            thumbprint = handler_settings.get("protectedSettingsCertThumbprint")
            ext.certificateThumbprint = thumbprint
            ext_handler.properties.extensions.append(ext)

class ExtensionManifest(object):
    def __init__(self, xml_text):
        if xml_text is None:
            raise ValueError("ExtensionManifest is None")
        logger.verb("Load ExtensionManifest.xml")
        self.pkg_list = ExtHandlerPackageList()
        self.parse(xml_text)

    def parse(self, xml_text):
        xml_doc = parse_doc(xml_text)
        packages = findall(xml_doc, "Plugin")
        for package in packages:
            version = findtext(package, "Version")
            uris = find(package, "Uris")
            uri_list = findall(uris, "Uri")
            uri_list = [gettext(x) for x in uri_list]
            package = ExtHandlerPackage()
            package.version = version
            for uri in uri_list:
                pkg_uri = ExtHandlerVersionUri()
                pkg_uri.uri = uri
                package.uris.append(pkg_uri)
            self.pkg_list.versions.append(package)

