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
        (the dots themselves are stripped out). When comparing versions the numeric components are compared numerically, while the
        other  components are compared lexicographically.

        NOTE: For entities with simpler version schemes (e.g. extensions and the Agent), use FlexibleVersion.

    """
    def __init__(self, version):
        self._version = version
        self._fragments = [
            int(x) if DistroVersion._number_re.match(x) else x
            for x in DistroVersion._fragment_re.split(self._version) if x != '' and x != '.'
        ]

    _fragment_re = re.compile(r'(\d+|[a-z]+|\.)', re.IGNORECASE)

    _number_re = re.compile(r'\d+')

    def __str__(self):
        return self._version

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return self._compare(other) == 0

    def __lt__(self, other):
        return self._compare(other) < 0

    def __le__(self, other):
        return self._compare(other) <= 0

    def __gt__(self, other):
        return self._compare(other) > 0

    def __ge__(self, other):
        return self._compare(other) >= 0

    def _compare(self, other):
        if isinstance(other, str):
            other = DistroVersion(other)

        if self._fragments < other._fragments:
            return -1
        if self._fragments > other._fragments:
            return 1
        return 0
