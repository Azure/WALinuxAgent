#!/usr/bin/env python
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

import os
import urllib2
import zipfile
import subprocess

def DownloadAndSaveFile(uri, file_path):
    src = urllib2.urlopen(uri)
    dest = open(file_path, 'wb')
    buf_size = 1024
    buf = src.read(buf_size)
    while(buf):
        dest.write(buf)
        buf = src.read(buf_size)

def Main():
    User='yuezh'
    Project='WALinuxAgent'
    Ref='2.1'
    TargetDir='.'

    Depo="{0}/{1}".format(User, Project)
    ZipFile='{0}-{1}.zip'.format(Project, Ref)
    ZipFileUri='https://github.com/{0}/archive/{1}.zip'.format(Depo, Ref)

    print "Download zip file..."
    DownloadAndSaveFile(ZipFileUri, ZipFile) 
    zfile = zipfile.ZipFile(ZipFile)
    zfile.extractall(TargetDir)

    os.remove(ZipFile)

if __name__ == '__main__':
    Main()
