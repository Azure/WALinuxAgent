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
from azurelinuxagent.metadata import DISTRO_NAME
import azurelinuxagent.distro.default.loader as default_loader


def get_distro_loader():
    try:
        logger.verb("Loading distro implemetation from: {0}", DISTRO_NAME)
        pkg_name = "azurelinuxagent.distro.{0}.loader".format(DISTRO_NAME)
        return __import__(pkg_name, fromlist="loader")
    except (ImportError, ValueError):
        logger.warn("Unable to load distro implemetation for {0}.", DISTRO_NAME)
        logger.warn("Use default distro implemetation instead.")
        return default_loader

DISTRO_LOADER = get_distro_loader()

def get_osutil():
    try:
        return DISTRO_LOADER.get_osutil()
    except AttributeError:
        return default_loader.get_osutil()

def get_handlers():
    try:
        return DISTRO_LOADER.get_handlers()
    except AttributeError:
        return default_loader.get_handlers()

