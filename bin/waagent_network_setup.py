#!/usr/bin/env python
#
# Azure Linux Agent
#
# Copyright 2015 Microsoft Corporation
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
# Requires Python 2.6 and Openssl 1.0+
#
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

import sys
import re
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.networkutil import AddFirewallRules


def _setup_firewall_rules():
    print("Setting up firewall rules")
    try:
        args = sys.argv[1:]
        dst_ip = ""
        uid = ""
        wait = ""

        # The command to call this would look something like this -
        # ExecStart=PYPATH /usr/sbin/waagent_network_setup.py --dst_ip=1.2.3.4 --uid=9999 [-w]
        for arg in args:
            if re.match("^([-/]*)dst_ip=(?P<dst_ip>[\d.]{7,})", arg):
                dst_ip = re.match("^([-/]*)dst_ip=(?P<dst_ip>[\d.]{7,})", arg).group('dst_ip')
            elif re.match("^([-/]*)uid=(?P<uid>[\d]+)", arg):
                uid = re.match("^([-/]*)uid=(?P<uid>[\d]+)", arg).group('uid')
            elif re.match("^([-/]*)w", arg):
                wait = "-w"

        AddFirewallRules.add_iptables_rules(wait, dst_ip, uid)
        print("Setting Firewall rules completed")
    except Exception as error:
        print("Unable to setup firewall rules: {0}".format(ustr(error)))
        sys.exit(1)


if __name__ == '__main__':
    """
    This file would be called by the waagent-network-setup service to bridge the gap between the system reboot and 
    waagent.service start. The sole purpose of this file is to setup firewall rules for the VM.
    
    The parameters for this file would be set in the unit file for the service, which would be created dynamically the 
    first time waagent.service starts. On every service restart, we would monitor the Wireserver IP and reset it in the 
    unit file if it changes.
    
    This service would run before the network would be setup, so we need to maintain state of the previous Wireserver IP
    to ensure we cover all attack vectors to the Wire IP.
    """
    _setup_firewall_rules()

