#!/usr/bin/python
#
# Windows Azure Linux Agent setup.py
#
# Copyright 2013 Microsoft Corporation
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

import sys
from distutils.core import setup
import imp

# waagent has no '.py' therefore create waagent module import manually.
__name__='setupmain'
waagent=imp.load_source('waagent','waagent') #prevent waagent.__main__ from executing
BUILDROOT=None

for a in range(len(sys.argv)):
    if sys.argv[a] == '--buildroot':
        BUILDROOT=sys.argv[a+1]

if BUILDROOT : # called by rpm-build
    waagent.PackagedInstall(BUILDROOT)
    
else : # python library module installation.
    setuptools.setup(name='waagent',
                     version=waagent.GuestAgentVersion,
                     description='Windows Azure Linux Agent',
                     url='http://launchpad.net/cloud-init/',
                     license='ApacheV2',
                     py_modules=['waagent'],
                     script_files=waagent.LibraryInstall(),
                 )


