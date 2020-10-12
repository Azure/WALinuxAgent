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

import os # pylint: disable=W0611
import re # pylint: disable=W0611
import pwd # pylint: disable=W0611
import shutil # pylint: disable=W0611
import socket # pylint: disable=W0611
import array # pylint: disable=W0611
import struct # pylint: disable=W0611
import fcntl # pylint: disable=W0611
import time # pylint: disable=W0611
import base64 # pylint: disable=W0611
import azurelinuxagent.common.logger as logger # pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil # pylint: disable=W0611
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil # pylint: disable=W0611
from azurelinuxagent.common.osutil.default import DefaultOSUtil


class DebianOSBaseUtil(DefaultOSUtil):

    def __init__(self):
        super(DebianOSBaseUtil, self).__init__()
        self.jit_enabled = True

    def restart_ssh_service(self):
        return shellutil.run("systemctl --job-mode=ignore-dependencies try-reload-or-restart ssh", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("service azurelinuxagent stop", chk_err=False)

    def start_agent_service(self):
        return shellutil.run("service azurelinuxagent start", chk_err=False)

    def start_network(self):
        pass

    def remove_rules_files(self, rules_files=""):
        pass

    def restore_rules_files(self, rules_files=""):
        pass

    def get_dhcp_lease_endpoint(self):
        return self.get_endpoint_from_leases_path('/var/lib/dhcp/dhclient.*.leases')


class DebianOSModernUtil(DebianOSBaseUtil):

    def __init__(self):
        super(DebianOSModernUtil, self).__init__()
        self.jit_enabled = True
        self.service_name = self.get_service_name()

    @staticmethod
    def get_service_name():
        return "walinuxagent"

    def stop_agent_service(self):
        return shellutil.run("systemctl stop {0}".format(self.service_name), chk_err=False)

    def start_agent_service(self):
        return shellutil.run("systemctl start {0}".format(self.service_name), chk_err=False)
