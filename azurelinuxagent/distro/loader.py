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

import azurelinuxagent.logger as logger
from azurelinuxagent.metadata import DistroName
import azurelinuxagent.distro.default.loader as defaultLoader


def GetDistroLoader():
    try:
        logger.Verbose("Loading distro implemetation from: {0}", DistroName)
        pkgName = "azurelinuxagent.distro.{0}.loader".format(DistroName)
        return __import__(pkgName, fromlist="loader")
    except ImportError as e:
        logger.Warn("Unable to load distro implemetation for {0}.", DistroName)
        logger.Warn("Use default distro implemetation instead.")
        return defaultLoader

distroLoader = GetDistroLoader()

def GetOSUtil():
    try:
        return distroLoader.GetOSUtil()
    except AttributeError:
        return defaultLoader.GetOSUtil()

def GetHandlers():
    try:
        return distroLoader.GetHandlers()
    except AttributeError:
        return defaultLoader.GetHandlers()

