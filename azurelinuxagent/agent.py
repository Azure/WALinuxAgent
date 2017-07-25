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

from __future__ import print_function

import os
import sys
import re
import subprocess
import traceback

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.event as event
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_VERSION, \
                                     DISTRO_NAME, DISTRO_VERSION, \
                                     PY_VERSION_MAJOR, PY_VERSION_MINOR, \
                                     PY_VERSION_MICRO, GOAL_STATE_AGENT_VERSION
from azurelinuxagent.common.osutil import get_osutil

class Agent(object):
    def __init__(self, verbose, conf_file_path=None):
        """
        Initialize agent running environment.
        """
        self.conf_file_path = conf_file_path
        self.osutil = get_osutil()

        #Init stdout log
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.STDOUT, level)

        #Init config
        conf_file_path = self.conf_file_path \
                if self.conf_file_path is not None \
                    else self.osutil.get_agent_conf_file_path()
        conf.load_conf_from_file(conf_file_path)

        #Init log
        verbose = verbose or conf.get_logs_verbose()
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.FILE, level,
                                 path="/var/log/waagent.log")
        logger.add_logger_appender(logger.AppenderType.CONSOLE, level,
                                 path="/dev/console")

        ext_log_dir = conf.get_ext_log_dir()
        try:
            if os.path.isfile(ext_log_dir):
                raise Exception("{0} is a file".format(ext_log_dir))
            if not os.path.isdir(ext_log_dir):
                os.makedirs(ext_log_dir)
        except Exception as e:
            logger.error(
                "Exception occurred while creating extension "
                "log directory {0}: {1}".format(ext_log_dir, e))

        #Init event reporter
        event.init_event_status(conf.get_lib_dir())
        event_dir = os.path.join(conf.get_lib_dir(), "events")
        event.init_event_logger(event_dir)
        event.enable_unhandled_err_dump("WALA")

    def daemon(self):
        """
        Run agent daemon
        """
        child_args = None \
            if self.conf_file_path is None \
                else "-configuration-path:{0}".format(self.conf_file_path)

        from azurelinuxagent.daemon import get_daemon_handler
        daemon_handler = get_daemon_handler()
        daemon_handler.run(child_args=child_args)

    def provision(self):
        """
        Run provision command
        """
        from azurelinuxagent.pa.provision import get_provision_handler
        provision_handler = get_provision_handler()
        provision_handler.run()

    def deprovision(self, force=False, deluser=False):
        """
        Run deprovision command
        """
        from azurelinuxagent.pa.deprovision import get_deprovision_handler
        deprovision_handler = get_deprovision_handler()
        deprovision_handler.run(force=force, deluser=deluser)

    def register_service(self):
        """
        Register agent as a service
        """
        print("Register {0} service".format(AGENT_NAME))
        self.osutil.register_agent_service()
        print("Stop {0} service".format(AGENT_NAME))
        self.osutil.stop_agent_service()
        print("Start {0} service".format(AGENT_NAME))
        self.osutil.start_agent_service()

    def run_exthandlers(self):
        """
        Run the update and extension handler
        """
        from azurelinuxagent.ga.update import get_update_handler
        update_handler = get_update_handler()
        update_handler.run()

def main(args=[]):
    """
    Parse command line arguments, exit with usage() on error.
    Invoke different methods according to different command
    """
    if len(args) <= 0:
        args = sys.argv[1:]
    command, force, verbose, conf_file_path = parse_args(args)
    if command == "version":
        version()
    elif command == "help":
        usage()
    elif command == "start":
        start(conf_file_path=conf_file_path)
    else:
        try:
            agent = Agent(verbose, conf_file_path=conf_file_path)
            if command == "deprovision+user":
                agent.deprovision(force, deluser=True)
            elif command == "deprovision":
                agent.deprovision(force, deluser=False)
            elif command == "provision":
                agent.provision()
            elif command == "register-service":
                agent.register_service()
            elif command == "daemon":
                agent.daemon()
            elif command == "run-exthandlers":
                agent.run_exthandlers()
        except Exception:
            logger.error(u"Failed to run '{0}': {1}",
                         command,
                         traceback.format_exc())

def parse_args(sys_args):
    """
    Parse command line arguments
    """
    cmd = "help"
    force = False
    verbose = False
    conf_file_path = None
    for a in sys_args:
        m = re.match("^(?:[-/]*)configuration-path:([\w/\.\-_]+)", a)
        if not m is None:
            conf_file_path = m.group(1)
            if not os.path.exists(conf_file_path):
                print("Error: Configuration file {0} does not exist".format(
                        conf_file_path), file=sys.stderr)
                usage()
                sys.exit(1)
        
        elif re.match("^([-/]*)deprovision\\+user", a):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", a):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", a):
            cmd = "daemon"
        elif re.match("^([-/]*)start", a):
            cmd = "start"
        elif re.match("^([-/]*)register-service", a):
            cmd = "register-service"
        elif re.match("^([-/]*)run-exthandlers", a):
            cmd = "run-exthandlers"
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
    return cmd, force, verbose, conf_file_path

def version():
    """
    Show agent version
    """
    print(("{0} running on {1} {2}".format(AGENT_LONG_VERSION,
                                           DISTRO_NAME,
                                           DISTRO_VERSION)))
    print("Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR,
                                       PY_VERSION_MINOR,
                                       PY_VERSION_MICRO))
    print("Goal state agent: {0}".format(GOAL_STATE_AGENT_VERSION))

def usage():
    """
    Show agent usage
    """
    print("")
    print((("usage: {0} [-verbose] [-force] [-help] "
           "-configuration-path:<path to configuration file>"
           "-deprovision[+user]|-register-service|-version|-daemon|-start|"
           "-run-exthandlers]"
           "").format(sys.argv[0])))
    print("")

def start(conf_file_path=None):
    """
    Start agent daemon in a background process and set stdout/stderr to
    /dev/null
    """
    devnull = open(os.devnull, 'w')
    args = [sys.argv[0], '-daemon']
    if conf_file_path is not None:
        args.append('-configuration-path:{0}'.format(conf_file_path))
    subprocess.Popen(args, stdout=devnull, stderr=devnull)

if __name__ == '__main__' :
    main()
