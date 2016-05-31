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

from azurelinuxagent.distro.default.distro import DefaultDistro
from azurelinuxagent.distro.ubuntu.osutil import Ubuntu14OSUtil, \
                                                 Ubuntu12OSUtil, \
                                                 UbuntuOSUtil, \
                                                 UbuntuSnappyOSUtil

from azurelinuxagent.distro.ubuntu.provision import UbuntuProvisionHandler
from azurelinuxagent.distro.ubuntu.deprovision import UbuntuDeprovisionHandler

class UbuntuDistro(DefaultDistro):
    def __init__(self):
        super(UbuntuDistro, self).__init__()
        self.osutil = UbuntuOSUtil()
        self.provision_handler = UbuntuProvisionHandler(self)
        self.deprovision_handler = UbuntuDeprovisionHandler(self)

class Ubuntu12Distro(DefaultDistro):
    def __init__(self):
        super(Ubuntu12Distro, self).__init__()
        self.osutil = Ubuntu12OSUtil()
        self.provision_handler = UbuntuProvisionHandler(self)
        self.deprovision_handler = UbuntuDeprovisionHandler(self)

class Ubuntu14Distro(DefaultDistro):
    def __init__(self):
        super(Ubuntu14Distro, self).__init__()
        self.osutil = Ubuntu14OSUtil()
        self.provision_handler = UbuntuProvisionHandler(self)
        self.deprovision_handler = UbuntuDeprovisionHandler(self)

class UbuntuSnappyDistro(DefaultDistro):
    def __init__(self):
        super(UbuntuSnappyDistro, self).__init__()
        self.osutil = UbuntuSnappyOSUtil()
        self.provision_handler = UbuntuProvisionHandler(self)
        self.deprovision_handler = UbuntuDeprovisionHandler(self)
