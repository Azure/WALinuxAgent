# Microsoft Azure Linux Agent
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

"""
Module agent
"""

import os
import sys
import re
import subprocess
from azurelinuxagent.metadata import AGENT_NAME, AGENT_LONG_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, \
                                     PY_VERSION_MAJOR, PY_VERSION_MINOR, \
                                     PY_VERSION_MICRO

from azurelinuxagent.distro.loader import get_distro

class Agent(object):
    def __init__(self, verbose):
        """
        Initialize agent running environment.
        """
        self.distro = get_distro();
        self.distro.init_handler.run(verbose)

    def daemon(self):
        """
        Run agent daemon
        """
        self.distro.daemon_handler.run()

    def deprovision(self, force=False, deluser=False):
        """
        Run deprovision command
        """
        self.distro.deprovision_handler.run(force=force, deluser=deluser)

    def register_service(self):
        """
        Register agent as a service
        """
        print("Register {0} service".format(AGENT_NAME))
        self.distro.osutil.register_agent_service()
        print("Start {0} service".format(AGENT_NAME))
        self.distro.osutil.start_agent_service()

def main():
    """
    Parse command line arguments, exit with usage() on error.
    Invoke different methods according to different command
    """
    command, force, verbose = parse_args(sys.argv[1:])
    if command == "version":
        version()
    elif command == "help":
        usage()
    elif command == "start":
        start()
    else:
        agent = Agent(verbose)
        if command == "deprovision+user":
            agent.deprovision(force, deluser=True)
        elif command == "deprovision":
            agent.deprovision(force, deluser=False)
        elif command == "register-service":
            agent.register_service()
        elif command == "daemon":
            agent.daemon()

def parse_args(sys_args):
    """
    Parse command line arguments
    """
    cmd = "help"
    force = False
    verbose = False
    for a in sys_args:
        if re.match("^([-/]*)deprovision\\+user", a):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", a):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", a):
            cmd = "daemon"
        elif re.match("^([-/]*)start", a):
            cmd = "start"
        elif re.match("^([-/]*)register-service", a):
            cmd = "register-service"
        elif re.match("^([-/]*)version", a):
            cmd = "version"
        elif re.match("^([-/]*)verbose", a):
            verbose = True
        elif re.match("^([-/]*)force", a):
            force = True
        elif re.match("^([-/]*)(help|usage|\\?)", a):
            cmd = "help"
        else:
            cmd = "help"
            break
    return cmd, force, verbose

def version():
    """
    Show agent version
    """
    print(("{0} running on {1} {2}".format(AGENT_LONG_VERSION, DISTRO_NAME,
                                          DISTRO_VERSION)))
    print("Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR, PY_VERSION_MINOR,
                                       PY_VERSION_MICRO))
def usage():
    """
    Show agent usage
    """
    print("")
    print((("usage: {0} [-verbose] [-force] [-help]"
           "-deprovision[+user]|-register-service|-version|-daemon|-start]"
           "").format(sys.argv[0])))
    print("")

def start():
    """
    Start agent daemon in a background process and set stdout/stderr to
    /dev/null
    """
    devnull = open(os.devnull, 'w')
    subprocess.Popen([sys.argv[0], '-daemon'], stdout=devnull, stderr=devnull)

