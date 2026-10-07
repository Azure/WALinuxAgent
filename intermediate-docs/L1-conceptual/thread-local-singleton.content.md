# Compose Content for: L1-conceptual/thread-local-singleton.md

Total files: 2

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/singletonperthread.py.SingletonPerThread`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolError`
- `%REPO%/azurelinuxagent/common/exception.py.OSUtilError`
- `%REPO%/azurelinuxagent/common/exception.py.ProtocolNotFoundError`
- `%REPO%/azurelinuxagent/common/exception.py.DhcpError`
- `%REPO%/azurelinuxagent/common/osutil/factory.py.get_osutil`
- `%REPO%/azurelinuxagent/common/dhcp.py.get_dhcp_handler`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py.cleanup_metadata_server_artifacts`
- `%REPO%/azurelinuxagent/common/protocol/metadata_server_migration_util.py.is_metadata_server_artifact_present`
- `%REPO%/azurelinuxagent/common/protocol/ovfenv.py.OvfEnv`
- `%REPO%/azurelinuxagent/common/protocol/wire.py.WireProtocol`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.KNOWN_WIRESERVER_IP`
- `%REPO%/azurelinuxagent/common/utils/restutil.py.IOErrorCounter`
- `%REPO%/azurelinuxagent/common/protocol/util.py.OVF_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/util.py.PROTOCOL_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/util.py.MAX_RETRY`
- `%REPO%/azurelinuxagent/common/protocol/util.py.PROBE_INTERVAL`
- `%REPO%/azurelinuxagent/common/protocol/util.py.ENDPOINT_FILE_NAME`
- `%REPO%/azurelinuxagent/common/protocol/util.py.PASSWORD_PATTERN`
- `%REPO%/azurelinuxagent/common/protocol/util.py.PASSWORD_REPLACEMENT`
- `%REPO%/azurelinuxagent/common/protocol/util.py.WIRE_PROTOCOL_NAME`
- `%REPO%/azurelinuxagent/co

### Source excerpt

````
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
#

import errno
import os
import re
import time
import threading

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common.singletonperthread import SingletonPerThread

from azurelinuxagent.common.exception import ProtocolError, OSUtilError, \
                                      ProtocolNotFoundError, DhcpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.dhcp import get_dhcp_handler
from azurelinuxagent.common.protocol.metadata_server_migration_util import cleanup_metadata_server_artifacts, \
                                                                           is_metadata_server_artifact_present
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP, \
                                                  IOErrorCounter

OVF_FILE_NAME = "ovf-env.xml"
PROTOCOL_FILE_NAME = "Protocol"
MAX_RETRY = 360
PROBE_INTERVAL = 10
ENDPOINT_FILE_NAME = "WireServerEndpoint"
PASSWORD_PATTERN = "<UserPassword>.*?<"
PASSWORD_REPLACEMENT = "<UserPassword>*<"
WIRE_PROTOCOL_NAME = "WireProtocol"

def get_protocol_util():
    return ProtocolUtil()

class ProtocolUtil(SingletonPerThread):
    """
    ProtocolUtil handles initialization for protocol instance. 2 protocol types
    are invoked, wire protocol
````

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass._instances`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass._lock`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass.__call__`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass.__call__.cls`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass.__call__.args`
- `%REPO%/azurelinuxagent/common/singletonperthread.py._SingletonPerThreadMetaClass.__call__.kwargs`
- `%REPO%/azurelinuxagent/common/singletonperthread.py.SingletonPerThread`

### Source excerpt

````
from threading import Lock, current_thread


class _SingletonPerThreadMetaClass(type):
    """ A metaclass that creates a SingletonPerThread base class when called. """
    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            # Object Name = className__threadName
            obj_name = "%s__%s" % (cls.__name__, current_thread().name)
            if obj_name not in cls._instances:
                cls._instances[obj_name] = super(_SingletonPerThreadMetaClass, cls).__call__(*args, **kwargs)
            return cls._instances[obj_name]


class SingletonPerThread(_SingletonPerThreadMetaClass('SingleObjectPerThreadMetaClass', (object,), {})):
    # This base class calls the metaclass above to create the singleton per thread object. This class provides an
    # abstraction over how to invoke the Metaclass so just inheriting this class makes the
    # child class a singleton per thread (As opposed to invoking the Metaclass separately for each derived classes)
    # More info here - https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    #
    # Usage:
    # Inheriting this class will create a Singleton per thread for that class
    # To delete the cached object of a class, call DerivedClassName.clear() to delete the object per thread
    # Note: If the thread dies and is recreated with the same thread name, the existing object would be reused
    # and no new object for the derived class would be created unless DerivedClassName.clear() is called explicitly to
    # delete the cache
    pass


````

---
