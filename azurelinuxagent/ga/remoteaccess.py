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
import os
import os.path
import traceback

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger

from datetime import datetime, timedelta

from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import RemoteAccessError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.protocol import get_protocol_util
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from azurelinuxagent.common.osutil import get_osutil

REMOTE_USR_EXPIRATION_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"
DATE_FORMAT = "%Y-%m-%d"
TRANSPORT_PRIVATE_CERT = "TransportPrivate.pem"
REMOTE_ACCESS_ACCOUNT_COMMENT = "JIT_Account"
MAX_TRY_ATTEMPT = 5
FAILED_ATTEMPT_THROTTLE = 1


def get_remote_access_handler():
    return RemoteAccessHandler()


class RemoteAccessHandler(object):
    def __init__(self):
        self.os_util = get_osutil()
        self.protocol_util = get_protocol_util()
        self.protocol = None
        self.cryptUtil = CryptUtil(conf.get_openssl_cmd())
        self.remote_access = None
        self.incarnation = 0
        self.error_message = ""

    def run(self):
        try:
            if self.os_util.jit_enabled:
                self.protocol = self.protocol_util.get_protocol()
                current_incarnation = self.protocol.get_incarnation()
                if self.incarnation != current_incarnation:
                    # something changed. Handle remote access if any.
                    self.incarnation = current_incarnation
                    self.remote_access = self.protocol.client.get_remote_access()
                    self.handle_remote_access()
        except Exception as e:
            msg = u"Exception processing remote access handler: {0} {1}".format(ustr(e), traceback.format_exc())
            logger.error(msg)
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.RemoteAccessHandling,
                      is_success=False,
                      message=msg)

    def handle_remote_access(self):
        # Get JIT user accounts.
        all_users = self.os_util.get_users()
        existing_jit_users = set(u[0] for u in all_users if self.validate_jit_user(u[4]))
        self.err_message = ""
        if self.remote_access is not None:
            goal_state_users = set(u.name for u in self.remote_access.user_list.users)
            for acc in self.remote_access.user_list.users:
                try:
                    raw_expiration = acc.expiration
                    account_expiration = datetime.strptime(raw_expiration, REMOTE_USR_EXPIRATION_FORMAT)
                    now = datetime.utcnow()
                    if acc.name not in existing_jit_users and now < account_expiration:
                        self.add_user(acc.name, acc.encrypted_password, account_expiration)
                    elif acc.name in existing_jit_users and now > account_expiration:
                        # user account expired, delete it.
                        logger.info("user {0} expired from remote_access".format(acc.name))
                        self.remove_user(acc.name)
                except RemoteAccessError as rae:
                    self.err_message = self.err_message + "Error processing user {0}. Exception: {1}"\
                        .format(acc.name, ustr(rae))
            for user in existing_jit_users:
                try:
                    if user not in goal_state_users:
                        # user explicitly removed
                        logger.info("User {0} removed from remote_access".format(user))
                        self.remove_user(user)
                except RemoteAccessError as rae:
                    self.err_message = self.err_message + "Error removing user {0}. Exception: {1}"\
                        .format(user, ustr(rae))
        else:
            # All users removed, remove any remaining JIT accounts.
            for user in existing_jit_users:
                try:
                    logger.info("User {0} removed from remote_access. remote_access empty".format(user))
                    self.remove_user(user)
                except RemoteAccessError as rae:
                    self.err_message = self.err_message + "Error removing user {0}. Exception: {1}"\
                        .format(user, ustr(rae))

    def validate_jit_user(self, comment):
        return comment == REMOTE_ACCESS_ACCOUNT_COMMENT

    def add_user(self, username, encrypted_password, account_expiration):
        try:
            expiration_date = (account_expiration + timedelta(days=1)).strftime(DATE_FORMAT)
            logger.verbose("Adding user {0} with expiration date {1}".format(username, expiration_date))
            self.os_util.useradd(username, expiration_date, REMOTE_ACCESS_ACCOUNT_COMMENT)
        except Exception as e:
            raise RemoteAccessError("Error adding user {0}. {1}".format(username, ustr(e)))
        try:
            prv_key = os.path.join(conf.get_lib_dir(), TRANSPORT_PRIVATE_CERT)
            pwd = self.cryptUtil.decrypt_secret(encrypted_password, prv_key)
            self.os_util.chpasswd(username, pwd, conf.get_password_cryptid(), conf.get_password_crypt_salt_len())
            self.os_util.conf_sudoer(username)
            logger.info("User '{0}' added successfully with expiration in {1}".format(username, expiration_date))
        except Exception as e:
            error = "Error adding user {0}. {1} ".format(username, str(e))
            try:
                self.handle_failed_create(username)
                error += "cleanup successful"
            except RemoteAccessError as rae:
                error += "and error cleaning up {0}".format(str(rae))
            raise RemoteAccessError("Error adding user {0} cleanup successful".format(username), ustr(e))

    def handle_failed_create(self, username):
        try:
            self.delete_user(username)
        except Exception as e:
            raise RemoteAccessError("Failed to clean up after account creation for {0}.".format(username), e)

    def remove_user(self, username):
        try:
            self.delete_user(username)
        except Exception as e:
            raise RemoteAccessError("Failed to delete user {0}".format(username), e)

    def delete_user(self, username):
        self.os_util.del_account(username)
        logger.info("User deleted {0}".format(username))
