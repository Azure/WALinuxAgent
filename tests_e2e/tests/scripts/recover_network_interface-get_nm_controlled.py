#!/usr/bin/env pypy3

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
#
import sys

from azurelinuxagent.common.osutil import get_osutil


def main():
    os_util = get_osutil()
    ifname = os_util.get_if_name()
    nm_controlled = os_util.get_nm_controlled(ifname)

    if nm_controlled:
        print("Interface is NM controlled")
    else:
        print("Interface is NOT NM controlled")

    sys.exit(0)


if __name__ == "__main__":
    main()
