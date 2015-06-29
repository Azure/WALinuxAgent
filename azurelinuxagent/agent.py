# Windows Azure Linux Agent
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
# Requires Python 2.4+ and Openssl 1.0+
#

import os
import sys
import re
import shutil
import time
import traceback
import threading
import subprocess
import azurelinuxagent.logger as logger
from azurelinuxagent.metadata import GuestAgentLongVersion, \
                                     DistroName, DistroVersion, DistroFullName
from azurelinuxagent.utils.osutil import OSUtil
from azurelinuxagent.handler import Handlers
import azurelinuxagent.utils.shellutil as shellutil
import azurelinuxagent.utils.fileutil as fileutil


def Init(verbose):
    Handlers.initHandler.init(verbose)
    
def Run():
    Handlers.runHandler.run()
    
def Deprovision(force=False, deluser=False):
    Handlers.deprovisionHandler.deprovision(force=force, deluser=deluser)
        
def ParseArgs(sysArgv):
    cmd = "help"
    force = False
    verbose = False
    for a in sysArgv:
        if re.match("^([-/]*)deprovision\+user", a):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", a):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", a):
            cmd = "daemon"
        elif re.match("^([-/]*)start", a):
            cmd = "start"
        elif re.match("^([-/]*)version", a):
            cmd = "version"
        elif re.match("^([-/]*)serialconsole", a):
            cmd = "serialconsole" 
        elif re.match("^([-/]*)verbose", a):
            verbose = True
        elif re.match("^([-/]*)force", a):
            force = True
        elif re.match("^([-/]*)(help|usage|\?)", a):
            cmd = "help"
        else:
            cmd = "help"
            break
    return cmd, force, verbose

def Version():
    print("{0} running on {1} {2}".format(GuestAgentLongVersion, DistroName,
                                          DistroVersion))
def Usage():
    print("")
    print(("usage: {0} [-verbose] [-force] "
           "[-help|-deprovision[+user]|-version|-serialconsole|-daemon|-start]"
           "").format(sys.argv[0]))
    print("")

def Start():
    devnull = open(os.devnull, 'w')
    subprocess.Popen([sys.argv[0], '-daemon'], stdout=devnull, stderr=devnull)

def Main():
    command, force, verbose = ParseArgs(sys.argv[1:])
    if command == "version":
        Version()
    elif command == "help":
        Usage()
    else: 
        Init(verbose)
        if command == "serialconsole":
            #TODO
            pass
        if command == "deprovision+user":
            Deprovision(force, deluser=True)
        elif command == "deprovision":
            Deprovision(force, deluser=False)
        elif command == "start":
            Start()
        elif command == "daemon":
            Run()
