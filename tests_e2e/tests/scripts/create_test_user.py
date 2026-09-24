#!/usr/bin/env pypy3

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
# Script used to exercise  osutil.useradd() and osutil.chpasswd().
#
# Creates a user with a random username and password and outputs the username.
#
# Use the --delete option to remove the user from the system.
#
import argparse
import os
import random
import string

from azurelinuxagent.common import conf
from azurelinuxagent.common.osutil.factory import get_osutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--delete', dest="delete", required=False)
    args = parser.parse_args()

    # The useradd/userdel commands are not on the default path on some distros; add /usr/sbin.
    os.environ["PATH"] = os.environ["PATH"] + ":/usr/sbin"

    osutil = get_osutil()

    if args.delete is not None:
        osutil.del_account(args.delete)
    else:
        username = 'test_user_' + ''.join(random.choice(string.digits) for _ in range(10))
        password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))

        osutil.useradd(username)
        osutil.chpasswd(username, password, conf.get_password_cryptid(), conf.get_password_crypt_salt_len())

        print(username)



if __name__ == "__main__":
    main()
