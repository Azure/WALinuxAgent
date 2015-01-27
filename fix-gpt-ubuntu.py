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

"""
WARNING: This script will remove all partitions in resource disk and create
a new one using the entire disk space.
"""
if __name__ == '__main__':
    print 'Umnout resource disk...'
    subprocess.call(['umount', '/dev/sdb1'])
    print 'Remove old partitions...'
    subprocess.call(['parted', '/dev/sdb', 'rm', '1'])
    subprocess.call(['parted', '/dev/sdb', 'rm', '2'])
    print 'Create new partition using the entire resource disk...'
    subprocess.call(['parted', '/dev/sdb','mkpart', 'primary', '0%', '100%'])
    subprocess.call(['mkfs.ext4', '/dev/sdb1'])
    subprocess.call(['mount', '/dev/sdb1', '/mnt'])
    print 'Resource disk(/dev/sdb1) is mounted at /mnt'

