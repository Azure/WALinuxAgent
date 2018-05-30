# Microsoft Azure Linux Agent
#
# Copyright Microsoft Corporation
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

import datetime
import glob
import json
import operator
import os
import os.path
import pwd
import random
import re
import shutil
import stat
import subprocess
import textwrap
import time
import traceback
import zipfile

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.version as version
import azurelinuxagent.common.protocol.wire
import azurelinuxagent.common.protocol.metadata as metadata

from datetime import datetime, timedelta
from pwd import getpwall
from azurelinuxagent.common.errorstate import ErrorState, ERROR_STATE_DELTA

from azurelinuxagent.common.event import add_event, WALAEventOperation, elapsed_milliseconds
from azurelinuxagent.common.exception import ExtensionError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol.restapi import ExtHandlerStatus, \
                                                    ExtensionStatus, \
                                                    ExtensionSubStatus, \
                                                    VMStatus, ExtHandler, \
                                                    get_properties, \
                                                    set_properties
from azurelinuxagent.common.protocol.metadata import MetadataProtocol
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.processutil import capture_from_process
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.common.osutil import get_osutil

REMOTE_USR_EXPIRATION_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"
DATE_FORMAT = "%Y-%m-%d"
TRANSPORT_PRIVATE_CERT = "TransportPrivate.pem"
REMOTE_ACCESS_ACCOUNT_COMMENT = "JIT Account"

def get_remote_access_handler():
    return RemoteAccessHandler()

class RemoteAccessHandler(object):
    def __init__(self):
        self.protocol_util = get_protocol_util()
        self.protocol = None
        self.os_util = None
        self.cryptUtil = CryptUtil(conf.get_openssl_cmd())

    def run(self):
        try:
            if self.os_util is not None:
                self.os_util = get_osutil()
            if self.os_util.jit_enabled:
                logger.verbose("Handle remote access updates")
                if self.protocol is None:
                    self.protocol = self.protocol_util.get_protocol()                
                self.protocol.client.update_goal_state()
                self.protocol.client.update_remote_access_conf(self.protocol.client.goal_state)
                remote_access = self.protocol.client.remote_access
                self.handle_remote_access(remote_access)
            else:
                logger.verbose("Non JIT enabled client.")
        except Exception as e:
            msg = u"Exception processing remote access handler: {0}".format(
                ustr(e))
            logger.warn(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.HandleRemoteAccess,
                      is_success=False,
                      message=msg)
            return        

    def handle_remote_access(self, remote_access):
        logger.verbose("Entered handle_remote_access")        
        if remote_access is not None:
            # Get existing users.
            all_users = self.os_util.get_users()
            jit_users = set()
            for usr in all_users:
                if usr[4] == REMOTE_ACCESS_ACCOUNT_COMMENT:
                    jit_users |= usr[0]          
            for acc in remote_access.user_list.users:
                raw_expiration = acc.expiration
                account_expiration = datetime.strptime(raw_expiration, REMOTE_USR_EXPIRATION_FORMAT)
                now = datetime.utcnow()
                try:
                    if acc.name not in jit_users and now < account_expiration:
                        self.add_user(acc.name, acc.encrypted_password, account_expiration)
                    if acc.name in jit_users and now > account_expiration:
                        self.remove_user(acc)
                except OSError as oe:
                    logger.error("handle_remote_access: {0}".format(oe.strerror))
                except Exception as e:
                    #TODO: Better error handling and cap to retry logic.
                    logger.error("handle_remote_access: {0}".format(str(e)))
        else:
            logger.verbose("handle_remote_access: remote_access is null")

    def add_user(self, username, encrypted_password, account_expiration):
        logger.info("add_user: Adding user {0} with expiration {1}".format(username, account_expiration))
        expiration_date = account_expiration + timedelta(days=1) - datetime.utcnow()
        self.os_util.useradd(username, expiration_date.days, REMOTE_ACCESS_ACCOUNT_COMMENT)
        cache_file = os.path.join(conf.get_lib_dir(), "remote_access_pwd.dat")
        prv_key = os.path.join(conf.get_lib_dir(), TRANSPORT_PRIVATE_CERT)
        pwd = self.cryptUtil.decrypt_secret(encrypted_password, prv_key, cache_file, None)   
        self.os_util.chpasswd(username, pwd, conf.get_password_cryptid(), conf.get_password_crypt_salt_len())
        self.os_util.conf_sudoer(username)
        logger.info("add_user: User '{0}' added successfully".format(username))
    
    def remove_user(self, username):
        logger.info("remove_user: Removing user {0}".format(username))
        self.os_util.del_account(username)
        logger.info("remove_user: User {0} removed successfully".format(username))
        
