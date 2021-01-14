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

# pylint: disable=W0611
import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction 
# pylint: enable=W0611

class ClearLinuxDeprovisionHandler(DeprovisionHandler):
    def __init__(self, distro):  # pylint: disable=W0231
        self.distro = distro

    def setup(self, deluser):
        warnings, actions = super(ClearLinuxDeprovisionHandler, self).setup(deluser)
        # Probably should just wipe /etc and /var here
        return warnings, actions
