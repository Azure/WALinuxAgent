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
#
import os
import copy
import re
import json
import xml.dom.minidom
import azurelinuxagent.logger as logger
from azurelinuxagent.future import text
import azurelinuxagent.utils.fileutil as fileutil

class ProtocolError(Exception):
    pass

class ProtocolNotFound(Exception):
    pass

def validata_param(name, val, expected_type):
    if val is None:
        raise ProtocolError("{0} is None".format(name))
    if not isinstance(val, expected_type):
        raise ProtocolError(("{0} type should be {1} not {2}"
                             "").format(name, expected_type, type(val)))

def set_properties(name, obj, data):
    if isinstance(obj, DataContract):
        validata_param("Property '{0}'".format(name), data, dict)
        for prob_name, prob_val in data.items():
            prob_full_name = "{0}.{1}".format(name, prob_name)
            try:
                prob =  getattr(obj, prob_name)
            except AttributeError:
                logger.warn("Unknown property: {0}", prob_full_name)
                continue
            prob = set_properties(prob_full_name, prob, prob_val)
            setattr(obj, prob_name, prob)
        return obj
    elif isinstance(obj, DataContractList):
        validata_param("List '{0}'".format(name), data, list)
        for item_data in data:
            item = obj.item_cls()
            item = set_properties(name, item, item_data)
            obj.append(item)
        return obj
    else:
        return data

def get_properties(obj):
    if isinstance(obj, DataContract):
        data = {}
        props = vars(obj)
        for prob_name, prob in list(props.items()):
            data[prob_name] = get_properties(prob)
        return data
    elif isinstance(obj, DataContractList):
        data = []
        for item in obj:
            item_data = get_properties(item)
            data.append(item_data)
        return data
    else:
        return obj

class DataContract(object):
    pass

class DataContractList(list):
    def __init__(self, item_cls):
        self.item_cls = item_cls

"""
Data contract between guest and host
"""
class VMInfo(DataContract):
    def __init__(self, subscriptionId=None, vmName=None):
        self.subscriptionId = subscriptionId
        self.vmName = vmName

class Cert(DataContract):
    def __init__(self, name=None, thumbprint=None, certificateDataUri=None):
        self.name = name
        self.thumbprint = thumbprint
        self.certificateDataUri = certificateDataUri

class CertList(DataContract):
    def __init__(self):
        self.certificates = DataContractList(Cert)

class Extension(DataContract):
    def __init__(self, name=None, sequenceNumber=None, publicSettings=None,
                 privateSettings=None, certificateThumbprint=None):
        self.name = name
        self.sequenceNumber = sequenceNumber
        self.publicSettings = publicSettings
        self.privateSettings = privateSettings
        self.certificateThumbprint = certificateThumbprint

class ExtHandlerProperties(DataContract):
    def __init__(self):
        self.version = None
        self.upgradePolicy = None
        self.state = None
        self.extensions = DataContractList(Extension)

class ExtHandlerVersionUri(DataContract):
    def __init__(self):
        self.uri = None

class ExtHandler(DataContract):
    def __init__(self, name=None):
        self.name = name
        self.properties = ExtHandlerProperties()
        self.versionUris = DataContractList(ExtHandlerVersionUri)

class ExtHandlerList(DataContract):
    def __init__(self):
        self.extHandlers = DataContractList(ExtHandler)

class ExtHandlerPackageUri(DataContract):
    def __init__(self, uri=None):
        self.uri = uri

class ExtHandlerPackage(DataContract):
    def __init__(self, version = None):
        self.version = version
        self.uris = DataContractList(ExtHandlerPackageUri)

class ExtHandlerPackageList(DataContract):
    def __init__(self):
        self.versions = DataContractList(ExtHandlerPackage)

class VMProperties(DataContract):
    def __init__(self, certificateThumbprint=None):
        #TODO need to confirm the property name
        self.certificateThumbprint = certificateThumbprint

class ProvisionStatus(DataContract):
    def __init__(self, status=None, subStatus=None, description=None):
        self.status = status
        self.subStatus = subStatus
        self.description = description
        self.properties = VMProperties()

class ExtensionSubStatus(DataContract):
    def __init__(self, name=None, status=None, code=None, message=None):
        self.name = name
        self.status = status
        self.code = code
        self.message = message

class ExtensionStatus(DataContract):
    def __init__(self, configurationAppliedTime=None, operation=None,
                 status=None, seq_no=None, code=None, message=None):
        self.configurationAppliedTime = configurationAppliedTime
        self.operation = operation
        self.status = status
        self.sequenceNumber = seq_no
        self.code = code
        self.message = message
        self.substatusList = DataContractList(ExtensionSubStatus)

class ExtHandlerStatus(DataContract):
    def __init__(self, name=None, version=None, status=None, message=None):
        self.name = name
        self.version = version
        self.status = status
        self.message = message
        self.extensions = DataContractList(text)

class VMAgentStatus(DataContract):
    def __init__(self, version=None, status=None, message=None):
        self.version = version
        self.status = status
        self.message = message
        self.extensionHandlers = DataContractList(ExtHandlerStatus)

class VMStatus(DataContract):
    def __init__(self):
        self.vmAgent = VMAgentStatus()

class TelemetryEventParam(DataContract):
    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value

class TelemetryEvent(DataContract):
    def __init__(self, eventId=None, providerId=None):
        self.eventId = eventId
        self.providerId = providerId
        self.parameters = DataContractList(TelemetryEventParam)

class TelemetryEventList(DataContract):
    def __init__(self):
        self.events = DataContractList(TelemetryEvent)

class Protocol(DataContract):

    def initialize(self):
        raise NotImplementedError()

    def get_vminfo(self):
        raise NotImplementedError()

    def get_certs(self):
        raise NotImplementedError()

    def get_ext_handlers(self):
        raise NotImplementedError()

    def get_ext_handler_pkgs(self, extension):
        raise NotImplementedError()

    def report_provision_status(self, provision_status):
        raise NotImplementedError()

    def report_vm_status(self, vm_status):
        raise NotImplementedError()

    def report_ext_status(self, ext_handler_name, ext_name, ext_status):
        raise NotImplementedError()

    def report_event(self, event):
        raise NotImplementedError()

