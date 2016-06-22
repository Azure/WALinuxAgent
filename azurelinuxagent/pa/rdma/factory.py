# Copyright 2016 Microsoft Corporation
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

import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.version import DISTRO_NAME
from azurelinuxagent.common.rdma import RDMAHandler
from .suse import SUSERDMAHandler


def get_rdma_handler(distro_name=DISTRO_NAME, distro_version=DISTRO_VERSION):
    """Return the handler object for RDMA driver handling"""
    if (
            distro_name == 'SUSE Linux Enterprise Server' and
            int(distro_version) > 11
    ):
        return SUSERDMAHandler()

    return RDMAHandler()
