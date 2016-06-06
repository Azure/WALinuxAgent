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

import os
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction

def del_resolv():
    if os.path.realpath('/etc/resolv.conf') != '/run/resolvconf/resolv.conf':
        logger.info("resolvconf is not configured. Removing /etc/resolv.conf")
        fileutil.rm_files('/etc/resolv.conf')
    else:
        logger.info("resolvconf is enabled; leaving /etc/resolv.conf intact")
        fileutil.rm_files('/etc/resolvconf/resolv.conf.d/tail',
                             '/etc/resolvconf/resolv.conf.d/originial')


class UbuntuDeprovisionHandler(DeprovisionHandler):
    def __init__(self):
        super(UbuntuDeprovisionHandler, self).__init__()

    def setup(self, deluser):
        warnings, actions = super(UbuntuDeprovisionHandler, self).setup(deluser)
        warnings.append("WARNING! Nameserver configuration in "
                        "/etc/resolvconf/resolv.conf.d/{tail,originial} "
                        "will be deleted.")
        actions.append(DeprovisionAction(del_resolv))
        return warnings, actions

