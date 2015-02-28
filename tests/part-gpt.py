#!/usr/bin/env python
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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

import subprocess

if __name__ == '__main__':
    subprocess.call(['umount', '/mnt/resource'])
    subprocess.call(['umount', '/mnt'])
    subprocess.call(['parted', '/dev/sdb', 'print'])
    subprocess.call(['parted', '/dev/sdb', 'rm', '1'])
    subprocess.call(['parted', '/dev/sdb', 'mklabel', 'gpt'])
    subprocess.call(['parted', '/dev/sdb', 'mkpart', 'primary', '0%', '50%'])
    subprocess.call(['parted', '/dev/sdb', 'mkpart', 'primary', '50%', '100%'])
