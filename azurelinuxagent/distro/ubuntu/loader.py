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

from azurelinuxagent.metadata import DISTRO_NAME, DISTRO_VERSION, DISTRO_FULL_NAME

def get_osutil():
    from  azurelinuxagent.distro.ubuntu.osutil import Ubuntu1204OSUtil, \
                                                      UbuntuOSUtil, \
                                                      Ubuntu14xOSUtil, \
                                                      UbuntuSnappyOSUtil

    if DISTRO_VERSION == "12.04":
        return Ubuntu1204OSUtil()
    elif DISTRO_VERSION == "14.04" or DISTRO_VERSION == "14.10":
        return Ubuntu14xOSUtil()
    elif DISTRO_FULL_NAME == "Snappy Ubuntu Core":
        return UbuntuSnappyOSUtil()
    else:
        return UbuntuOSUtil()

def get_handlers():
    from azurelinuxagent.distro.ubuntu.handlerFactory import UbuntuHandlerFactory
    return UbuntuHandlerFactory()

