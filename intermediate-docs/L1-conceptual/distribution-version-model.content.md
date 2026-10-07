# Compose Content for: L1-conceptual/distribution-version-model.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__init__`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__init__.self`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__init__.version`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion._fragment_re`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion._number_re`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__str__`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__str__.self`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__repr__`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__repr__.self`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__eq__`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__eq__.self`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__eq__.other`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion._compare`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__lt__`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__lt__.self`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__lt__.other`
- `%REPO%/azurelinuxagent/common/utils/distro_version.py.DistroVersion.__le__`
- `%REPO%/azurel

### Source excerpt

````
# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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

"""
"""

import re


class DistroVersion(object):
    """
        Distro versions (as exposed by azurelinuxagent.common.version.DISTRO_VERSION) can be very arbitrary:

            9.2.0
            0.0.0.0_99496
            10.0_RC2
            1.4-rolling-202402090309
            2015.11-git
            2023
            2023.02.1
            2.1-systemd-rc1
            2308a
            3.11.2-dev20240212t1512utc-autotag
            3.11.2-rc.1
            3.1.22-1.8
            8.1.3-p1-24838
            8.1.3-p8-khilan.unadkat-08415223c9a99546b566df0dbc683ffa378cfd77
            9.13.1P8X1
            9.13.1RC1
            9.2.0-beta1-25971
            a
            ArrayOS
            bookworm/sid
            Clawhammer__9.14.0
            FFFF
            h
            JNPR-11.0-20200922.4042921_build
            lighthouse-23.10.0
            Lighthouse__9.13.1
            linux-os-31700
            Mightysquirrel__9.15.0
            n/a
            NAME="SLES"
            ngfw-6.10.13.26655.fips.2
            r11427-9ce6aa9d8d
            SonicOSX 7.1.1-7047-R3003-HF24239
            unstable
            vsbc-x86_pi3-6.10.3
            vsbc-x86_pi3-6.12.2pre02

        The DistroVersion allows to compare these versions following an strategy similar to the now deprecated distutils.LooseVersion:
        versions consist of a series of sequences of numbers, alphabetic characters, or any other characters, optionally separated dots
        (the dots themselves are stripped out). When comparing versions the nume
````

---
