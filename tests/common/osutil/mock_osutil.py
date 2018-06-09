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

from azurelinuxagent.common.osutil.default import DefaultOSUtil

class MockOSUtil(DefaultOSUtil):
    def __init__(self):
        self.all_users = {}
        self.sudo_users = set()
        self.jit_enabled = True

    def useradd(self, username, expiration=None, comment=None):
        if username == "":
            raise Exception("test exception for bad username")
        if username in self.all_users:
            raise Exception("test exception, user already exists")
        self.all_users[username] = (username, None, None, None, comment, None, None, expiration)

    def conf_sudoer(self, username, nopasswd=False, remove=False):
        if not remove:
            self.sudo_users.add(username)
        else:
            self.sudo_users.remove(username)

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if password == "":
            raise Exception("test exception for bad password")
        user = self.all_users[username]
        self.all_users[username] = (user[0], password, user[2], user[3], user[4], user[5], user[6], user[7])

    def del_account(self, username):
        if username == "":
            raise Exception("test exception, bad data")
        if username not in self.all_users:
            raise Exception("test exception, user does not exist to delete")
        self.all_users.pop(username)

    def get_users(self):
        return self.all_users.values()