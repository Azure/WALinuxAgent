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

import os.path
import signal
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.future import read_input
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util

class DeprovisionAction(object):
    def __init__(self, func, args=[], kwargs={}):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def invoke(self):
        self.func(*self.args, **self.kwargs)

class DeprovisionHandler(object):
    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()
        self.actions_running = False
        signal.signal(signal.SIGINT, self.handle_interrupt_signal)

    def del_root_password(self, warnings, actions):
        warnings.append("WARNING! root password will be disabled. "
                        "You will not be able to login as root.")

        actions.append(DeprovisionAction(self.osutil.del_root_password))

    def del_user(self, warnings, actions):

        try:
            ovfenv = self.protocol_util.get_ovf_env()
        except ProtocolError:
            warnings.append("WARNING! ovf-env.xml is not found.")
            warnings.append("WARNING! Skip delete user.")
            return

        username = ovfenv.username
        warnings.append(("WARNING! {0} account and entire home directory "
                         "will be deleted.").format(username))
        actions.append(DeprovisionAction(self.osutil.del_account, 
                                         [username]))


    def regen_ssh_host_key(self, warnings, actions):
        warnings.append("WARNING! All SSH host key pairs will be deleted.")
        actions.append(DeprovisionAction(fileutil.rm_files,
                        [conf.get_ssh_key_glob()]))

    def stop_agent_service(self, warnings, actions):
        warnings.append("WARNING! The waagent service will be stopped.")
        actions.append(DeprovisionAction(self.osutil.stop_agent_service))

    def del_files(self, warnings, actions):
        files_to_del = ['/root/.bash_history', '/var/log/waagent.log']
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))

    def del_resolv(self, warnings, actions):
        warnings.append("WARNING! /etc/resolv.conf will be deleted.")
        files_to_del = ["/etc/resolv.conf"]
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))

    def del_dhcp_lease(self, warnings, actions):
        warnings.append("WARNING! Cached DHCP leases will be deleted.")
        dirs_to_del = ["/var/lib/dhclient", "/var/lib/dhcpcd", "/var/lib/dhcp"]
        actions.append(DeprovisionAction(fileutil.rm_dirs, dirs_to_del))

        # For Freebsd, NM controlled
        actions.append(DeprovisionAction(fileutil.rm_files, ["/var/db/dhclient.leases.hn0",
                                                             "/var/lib/NetworkManager/dhclient-*.lease"]))

    def del_lib_dir(self, warnings, actions):
        dirs_to_del = [conf.get_lib_dir()]
        actions.append(DeprovisionAction(fileutil.rm_dirs, dirs_to_del))

    def cloud_init_directories(self):
        return ["/var/lib/cloud/instance",
            "/var/lib/cloud/instances/",
            "/var/lib/cloud/data"]

    def cloud_init_files(self):
        return ["/etc/sudoers.d/90-cloud-init-users"]

    def del_cloud_init(self, warnings, actions):
        dirs = [d for d in self.cloud_init_directories() if os.path.isdir(d)]
        if len(dirs) > 0:
            actions.append(DeprovisionAction(fileutil.rm_dirs, dirs))

        files = [f for f in self.cloud_init_files() if os.path.isfile(f)]
        if len(files) > 0:
            actions.append(DeprovisionAction(fileutil.rm_files, files))

    def reset_hostname(self, warnings, actions):
        localhost = ["localhost.localdomain"]
        actions.append(DeprovisionAction(self.osutil.set_hostname, 
                                         localhost))
        actions.append(DeprovisionAction(self.osutil.set_dhcp_hostname, 
                                         localhost))

    def setup(self, deluser):
        warnings = []
        actions = []

        self.stop_agent_service(warnings, actions)
        if conf.get_regenerate_ssh_host_key():
            self.regen_ssh_host_key(warnings, actions)

        self.del_dhcp_lease(warnings, actions)
        self.reset_hostname(warnings, actions)

        if conf.get_delete_root_password():
            self.del_root_password(warnings, actions)

        self.del_cloud_init(warnings, actions)
        self.del_lib_dir(warnings, actions)
        self.del_files(warnings, actions)
        self.del_resolv(warnings, actions)

        if deluser:
            self.del_user(warnings, actions)

        return warnings, actions

    def run(self, force=False, deluser=False):
        warnings, actions = self.setup(deluser)
        for warning in warnings:
            print(warning)

        if not force:
            confirm = read_input("Do you want to proceed (y/n)")
            if not confirm.lower().startswith('y'):
                return

        self.actions_running = True
        for action in actions:
            action.invoke()

    def handle_interrupt_signal(self, signum, frame):
        if not self.actions_running:
            print("Deprovision is interrupted.")
            sys.exit(0)

        print ('Deprovisioning may not be interrupted.')
        return


