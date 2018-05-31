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
from azurelinuxagent.common.errorstate import ErrorState

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
MAX_TRY_ATTEMPT = 5
FAILED_ATTEMPT_THROTTLE = 1

def get_remote_access_handler():
    return RemoteAccessHandler()

class RemoteAccessHandler(object):
    def __init__(self):
        self.protocol_util = get_protocol_util()
        self.protocol = None
        self.os_util = None
        self.cryptUtil = CryptUtil(conf.get_openssl_cmd())
        self.remote_access = None

    def run(self):
        try:
            if self.os_util is None:
                self.os_util = get_osutil()
            if self.os_util.jit_enabled:
                self.protocol = self.protocol_util.get_protocol()
                self.protocol.client.update_goal_state(True)
                self.protocol.client.update_remote_access_conf(self.protocol.client.goal_state)
                if self.remote_access is None or self.remote_access.incarnation != self.protocol.client.remote_access.incarnation:
                    self.remote_access = self.protocol.client.remote_access
                    self.handle_remote_access()
            else:
                logger.info("Non JIT enabled client.")
        except Exception as e:
            msg = u"Exception processing remote access handler: {0}".format(
                ustr(e))
            logger.error(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.HandleRemoteAccess,
                      is_success=False,
                      message=msg)
            return     

    def handle_remote_access(self):
        logger.verbose("Entered handle_remote_access")        
        if self.remote_access is not None:
            # Get JIT user accounts.
            all_users = self.os_util.get_users()
            jit_users = set()
            for usr in all_users:
                if usr[4] == REMOTE_ACCESS_ACCOUNT_COMMENT:
                    jit_users.add(usr[0])     
            for acc in self.remote_access.user_list.users:
                raw_expiration = acc.expiration
                account_expiration = datetime.strptime(raw_expiration, REMOTE_USR_EXPIRATION_FORMAT)
                now = datetime.utcnow()
                if acc.name not in jit_users and now < account_expiration:
                    self.add_user(acc.name, acc.encrypted_password, account_expiration)

    def add_user(self, username, encrypted_password, account_expiration):
        created = False
        try:
            expiration_date = account_expiration + timedelta(days=1) - datetime.utcnow()
            logger.verbose("[RemoteAccessHandler::add_user]: Adding user {0} with expiration in {1} day(s)".format(username, expiration_date.days))
            self.os_util.useradd(username, expiration_date.days, REMOTE_ACCESS_ACCOUNT_COMMENT)
            created = True
            cache_file = os.path.join(conf.get_lib_dir(), "remote_access_pwd.dat")
            prv_key = os.path.join(conf.get_lib_dir(), TRANSPORT_PRIVATE_CERT)
            pwd = self.cryptUtil.decrypt_secret(encrypted_password, prv_key, cache_file, None)
            self.os_util.chpasswd(username, pwd, conf.get_password_cryptid(), conf.get_password_crypt_salt_len())
            self.os_util.conf_sudoer(username)
            logger.info("[RemoteAccessHandler::add_user]: User '{0}' added successfully with expiration in {1} day(s)".format(username, expiration_date.days))
            return
        except OSError as oe:
            self.handle_failed_create(username, oe.strerror, created)
        except Exception as e:
            self.handle_failed_create(username, str(e), created)
        logger.warn("[RemoteAccessHandler::add_user]: Unable to add user {0}. Will not try again for this incarnation.".format(username))
        return

    def handle_failed_create(self, username, error_message, created):
        logger.error("[RemoteAccessHandler::failed_create]: Error adding user {0}. {1}".format(username, error_message))
        if created:
            try:
                self.delete_user(username)
            except OSError as oe:
                logger.error("[RemoteAccessHandler::failed_create]: Failed to clean up after account creation for {0}. {1}".format(username, oe.strerror()))
            except Exception as e:
                logger.error("[RemoteAccessHandler::failed_create]: Failed to clean up after account creation for {0}. {1}".format(username, str(e)))

    def delete_user(self, username):
        self.os_util.del_account(username)
        logger.info("[RemoteAccessHandler::delete_user]: User deleted {0}".format(username))        
