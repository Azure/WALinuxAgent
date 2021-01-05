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

import os
import os.path
import traceback
from datetime import datetime, timedelta

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION

REMOTE_USR_EXPIRATION_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"
DATE_FORMAT = "%Y-%m-%d"
TRANSPORT_PRIVATE_CERT = "TransportPrivate.pem"
REMOTE_ACCESS_ACCOUNT_COMMENT = "JIT_Account"
MAX_TRY_ATTEMPT = 5
FAILED_ATTEMPT_THROTTLE = 1


def get_remote_access_handler(protocol):
    return RemoteAccessHandler(protocol)


class RemoteAccessHandler(object): 
    def __init__(self, protocol):
        self._os_util = get_osutil()
        self._protocol = protocol
        self._cryptUtil = CryptUtil(conf.get_openssl_cmd())
        self._remote_access = None
        self._incarnation = 0
        self._check_existing_jit_users = True

    def run(self):
        try:
            if self._os_util.jit_enabled:
                current_incarnation = self._protocol.get_incarnation()
                if self._incarnation != current_incarnation:
                    # something changed. Handle remote access if any.
                    self._incarnation = current_incarnation
                    self._remote_access = self._protocol.client.get_remote_access()
                    self._handle_remote_access()
        except Exception as e:
            msg = u"Exception processing goal state for remote access users: {0} {1}".format(ustr(e), traceback.format_exc())
            add_event(AGENT_NAME,
                      version=CURRENT_VERSION,
                      op=WALAEventOperation.RemoteAccessHandling,
                      is_success=False,
                      message=msg)

    def _get_existing_jit_users(self):
        all_users = self._os_util.get_users()
        return set(u[0] for u in all_users if self._is_jit_user(u[4]))

    def _handle_remote_access(self):
        if self._remote_access is not None:
            logger.info("Processing remote access users in goal state.")

            self._check_existing_jit_users = True

            existing_jit_users = self._get_existing_jit_users()
            goal_state_users = set(u.name for u in self._remote_access.user_list.users)

            for acc in self._remote_access.user_list.users:
                try:
                    raw_expiration = acc.expiration
                    account_expiration = datetime.strptime(raw_expiration, REMOTE_USR_EXPIRATION_FORMAT)
                    now = datetime.utcnow()
                    if acc.name not in existing_jit_users and now < account_expiration:
                        self._add_user(acc.name, acc.encrypted_password, account_expiration)
                    elif acc.name in existing_jit_users and now > account_expiration:
                        # user account expired, delete it.
                        logger.info("Remote access user '{0}' expired.", acc.name)
                        self._remove_user(acc.name)
                except Exception as e:
                    logger.error("Error processing remote access user '{0}' - {1}", acc.name, ustr(e))

            for user in existing_jit_users:
                try:
                    if user not in goal_state_users:
                        # user explicitly removed
                        self._remove_user(user)
                except Exception as e:
                    logger.error("Error removing remote access user '{0}' - {1}", user, ustr(e))
        else:
            # There are no JIT users in the goal state; that may mean that they were removed or that they
            # were never added. Enumerating the users on the current vm can be very slow and this path is hit
            # on each goal state; we use self._check_existing_jit_users to avoid enumerating the users
            # every single time.
            if self._check_existing_jit_users:
                logger.info("Looking for existing remote access users.")

                existing_jit_users = self._get_existing_jit_users()

                remove_user_errors = False

                for user in existing_jit_users:
                    try:
                        self._remove_user(user)
                    except Exception as e:
                        logger.error("Error removing remote access user '{0}' - {1}", user, ustr(e))
                        remove_user_errors = True

                if not remove_user_errors:
                    self._check_existing_jit_users = False

    @staticmethod
    def _is_jit_user(comment):
        return comment == REMOTE_ACCESS_ACCOUNT_COMMENT

    def _add_user(self, username, encrypted_password, account_expiration):
        user_added = False

        try:
            expiration_date = (account_expiration + timedelta(days=1)).strftime(DATE_FORMAT)
            logger.info("Adding remote access user '{0}' with expiration date {1}", username, expiration_date)
            self._os_util.useradd(username, expiration_date, REMOTE_ACCESS_ACCOUNT_COMMENT)
            user_added = True

            logger.info("Adding remote access user '{0}' to sudoers", username)
            prv_key = os.path.join(conf.get_lib_dir(), TRANSPORT_PRIVATE_CERT)
            pwd = self._cryptUtil.decrypt_secret(encrypted_password, prv_key)
            self._os_util.chpasswd(username, pwd, conf.get_password_cryptid(), conf.get_password_crypt_salt_len())
            self._os_util.conf_sudoer(username)
        except Exception:
            if user_added:
                self._remove_user(username)
            raise

    def _remove_user(self, username):
        logger.info("Removing remote access user '{0}'", username)
        self._os_util.del_account(username)

