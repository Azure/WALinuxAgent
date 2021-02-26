# Microsoft Azure Linux Agent
#
# Copyright 2019 Microsoft Corporation
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

from azurelinuxagent.common.exception import ProtocolError
import azurelinuxagent.common.logger as logger

# pylint: disable=W0105
"""
Base class for data contracts between guest and host and utilities to manipulate the properties in those contracts
""" 
# pylint: enable=W0105


class DataContract(object):
    pass


class DataContractList(list):
    def __init__(self, item_cls):  # pylint: disable=W0231
        self.item_cls = item_cls


def validate_param(name, val, expected_type):
    if val is None:
        raise ProtocolError("{0} is None".format(name))
    if not isinstance(val, expected_type):
        raise ProtocolError(("{0} type should be {1} not {2}"
                             "").format(name, expected_type, type(val)))


def set_properties(name, obj, data):
    if isinstance(obj, DataContract):
        validate_param("Property '{0}'".format(name), data, dict)
        for prob_name, prob_val in data.items():
            prob_full_name = "{0}.{1}".format(name, prob_name)
            try:
                prob = getattr(obj, prob_name)
            except AttributeError:
                logger.warn("Unknown property: {0}", prob_full_name)
                continue
            prob = set_properties(prob_full_name, prob, prob_val)
            setattr(obj, prob_name, prob)
        return obj
    elif isinstance(obj, DataContractList):
        validate_param("List '{0}'".format(name), data, list)
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
