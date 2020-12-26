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

import glob
import os.path
import re
import signal
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.common import version
from azurelinuxagent.common.exception import ProtocolError
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.ga.exthandlers import HANDLER_COMPLETE_NAME_PATTERN


def read_input(message):
    if sys.version_info[0] >= 3:
        return input(message)
    else:
        # This is not defined in python3, and the linter will thus 
        # throw an undefined-variable<E0602> error on this line.
        # Suppress it here.
        return raw_input(message)  # pylint: disable=E0602


class DeprovisionAction(object):
    def __init__(self, func, args=None, kwargs=None):
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
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

    def del_dirs(self, warnings, actions):  # pylint: disable=W0613
        dirs = [conf.get_lib_dir(), conf.get_ext_log_dir()]
        actions.append(DeprovisionAction(fileutil.rm_dirs, dirs))

    def del_files(self, warnings, actions):  # pylint: disable=W0613
        files = ['/root/.bash_history', conf.get_agent_log_file()]
        actions.append(DeprovisionAction(fileutil.rm_files, files))

        # For OpenBSD
        actions.append(DeprovisionAction(fileutil.rm_files,
                                         ["/etc/random.seed",
                                          "/var/db/host.random",
                                          "/etc/isakmpd/local.pub",
                                          "/etc/isakmpd/private/local.key",
                                          "/etc/iked/private/local.key",
                                          "/etc/iked/local.pub"]))

    def del_resolv(self, warnings, actions):
        warnings.append("WARNING! /etc/resolv.conf will be deleted.")
        files_to_del = ["/etc/resolv.conf"]
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))

    def del_dhcp_lease(self, warnings, actions):
        warnings.append("WARNING! Cached DHCP leases will be deleted.")
        dirs_to_del = ["/var/lib/dhclient", "/var/lib/dhcpcd", "/var/lib/dhcp"]
        actions.append(DeprovisionAction(fileutil.rm_dirs, dirs_to_del))

        # For FreeBSD and OpenBSD
        actions.append(DeprovisionAction(fileutil.rm_files,
                                         ["/var/db/dhclient.leases.*"]))

        # For FreeBSD, NM controlled
        actions.append(DeprovisionAction(fileutil.rm_files,
                                         ["/var/lib/NetworkManager/dhclient-*.lease"]))

    def del_ext_handler_files(self, warnings, actions):  # pylint: disable=W0613
        ext_dirs = [d for d in os.listdir(conf.get_lib_dir())
                    if os.path.isdir(os.path.join(conf.get_lib_dir(), d))
                    and re.match(HANDLER_COMPLETE_NAME_PATTERN, d) is not None
                    and not version.is_agent_path(d)]

        for ext_dir in ext_dirs:
            ext_base = os.path.join(conf.get_lib_dir(), ext_dir)
            files = glob.glob(os.path.join(ext_base, 'status', '*.status'))
            files += glob.glob(os.path.join(ext_base, 'config', '*.settings'))
            files += glob.glob(os.path.join(ext_base, 'config', 'HandlerStatus'))
            files += glob.glob(os.path.join(ext_base, 'mrseq'))

            if len(files) > 0:
                actions.append(DeprovisionAction(fileutil.rm_files, files))

    def del_lib_dir_files(self, warnings, actions):  # pylint: disable=W0613
        known_files = [
            'HostingEnvironmentConfig.xml',
            'Incarnation',
            'partition',
            'Protocol',
            'SharedConfig.xml',
            'WireServerEndpoint'
        ]
        known_files_glob = [
            'Extensions.*.xml',
            'ExtensionsConfig.*.xml',
            'GoalState.*.xml'
        ]

        lib_dir = conf.get_lib_dir()
        files = [f for f in \
                    [os.path.join(lib_dir, kf) for kf in known_files] \
                        if os.path.isfile(f)]
        for p in known_files_glob:
            files += glob.glob(os.path.join(lib_dir, p))

        if len(files) > 0:
            actions.append(DeprovisionAction(fileutil.rm_files, files))

    def reset_hostname(self, warnings, actions):  # pylint: disable=W0613
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

        self.del_dirs(warnings, actions)
        self.del_files(warnings, actions)
        self.del_resolv(warnings, actions)

        if deluser:
            self.del_user(warnings, actions)

        return warnings, actions

    def setup_changed_unique_id(self):
        warnings = []
        actions = []

        self.del_dhcp_lease(warnings, actions)
        self.del_lib_dir_files(warnings, actions)
        self.del_ext_handler_files(warnings, actions)

        return warnings, actions

    def run(self, force=False, deluser=False):
        warnings, actions = self.setup(deluser)

        self.do_warnings(warnings)
        if self.do_confirmation(force=force):
            self.do_actions(actions)

    def run_changed_unique_id(self):
        '''
        Clean-up files and directories that may interfere when the VM unique
        identifier has changed.

        While users *should* manually deprovision a VM, the files removed by
        this routine will help keep the agent from getting confused
        (since incarnation and extension settings, among other items, will 
        no longer be monotonically increasing).
        '''
        warnings, actions = self.setup_changed_unique_id()

        self.do_warnings(warnings)
        self.do_actions(actions)

    def do_actions(self, actions):
        self.actions_running = True
        for action in actions:
            action.invoke()
        self.actions_running = False

    def do_confirmation(self, force=False):
        if force:
            return True

        confirm = read_input("Do you want to proceed (y/n)")
        return True if confirm.lower().startswith('y') else False
    
    def do_warnings(self, warnings):
        for warning in warnings:
            print(warning)

    def handle_interrupt_signal(self, signum, frame):  # pylint: disable=W0613
        if not self.actions_running:
            print("Deprovision is interrupted.")
            sys.exit(0)

        print ('Deprovisioning may not be interrupted.')
        return
