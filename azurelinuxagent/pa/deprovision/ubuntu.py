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
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
    DeprovisionAction


class UbuntuDeprovisionHandler(DeprovisionHandler):
    def __init__(self):
        super(UbuntuDeprovisionHandler, self).__init__()

    def del_resolv(self, warnings, actions):
        if os.path.realpath(
                '/etc/resolv.conf') != '/run/resolvconf/resolv.conf':
            warnings.append("WARNING! /etc/resolv.conf will be deleted.")
            files_to_del = ["/etc/resolv.conf"]
            actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))
        else:
            warnings.append("WARNING! /etc/resolvconf/resolv.conf.d/tail "
                            "and /etc/resolvconf/resolv.conf.d/original will "
                            "be deleted.")
            files_to_del = ["/etc/resolvconf/resolv.conf.d/tail",
                            "/etc/resolvconf/resolv.conf.d/original"]
            actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))
