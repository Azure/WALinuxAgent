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
# Requires Python 2.6+ and Openssl 1.0+
#

"""
Module agent
"""

from __future__ import print_function

import os
import re
import subprocess
import sys
import threading
import traceback

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.event as event
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logcollector import LogCollector, OUTPUT_RESULTS_FILE_PATH
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_VERSION, AGENT_VERSION, \
    DISTRO_NAME, DISTRO_VERSION, \
    PY_VERSION_MAJOR, PY_VERSION_MINOR, \
    PY_VERSION_MICRO, GOAL_STATE_AGENT_VERSION, \
    get_daemon_version, set_daemon_version
from azurelinuxagent.pa.provision.default import ProvisionHandler


class Agent(object):
    def __init__(self, verbose, conf_file_path=None):
        """
        Initialize agent running environment.
        """
        self.conf_file_path = conf_file_path
        self.osutil = get_osutil()

        # Init stdout log
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.STDOUT, level)

        # Init config
        conf_file_path = self.conf_file_path \
                if self.conf_file_path is not None \
                    else self.osutil.get_agent_conf_file_path()
        conf.load_conf_from_file(conf_file_path)

        # Init log
        verbose = verbose or conf.get_logs_verbose()
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.FILE, level, path=conf.get_agent_log_file())

        # echo the log to /dev/console if the machine will be provisioned
        if conf.get_logs_console() and not ProvisionHandler.is_provisioned():
            self.__add_console_appender(level)

        if event.send_logs_to_telemetry():
            logger.add_logger_appender(logger.AppenderType.TELEMETRY,
                                       logger.LogLevel.WARNING,
                                       path=event.add_log_event)

        ext_log_dir = conf.get_ext_log_dir()
        try:
            if os.path.isfile(ext_log_dir):
                raise Exception("{0} is a file".format(ext_log_dir))
            if not os.path.isdir(ext_log_dir):
                fileutil.mkdir(ext_log_dir, mode=0o755, owner="root")
        except Exception as e: # pylint: disable=C0103
            logger.error(
                "Exception occurred while creating extension "
                "log directory {0}: {1}".format(ext_log_dir, e))

        # Init event reporter
        # Note that the reporter is not fully initialized here yet. Some telemetry fields are filled with data
        # originating from the goal state or IMDS, which requires a WireProtocol instance. Once a protocol
        # has been established, those fields must be explicitly initialized using
        # initialize_event_logger_vminfo_common_parameters(). Any events created before that initialization
        # will contain dummy values on those fields.
        event.init_event_status(conf.get_lib_dir())
        event_dir = os.path.join(conf.get_lib_dir(), event.EVENTS_DIRECTORY)
        event.init_event_logger(event_dir)
        event.enable_unhandled_err_dump("WALA")

    def __add_console_appender(self, level):
        logger.add_logger_appender(logger.AppenderType.CONSOLE, level, path="/dev/console")

    def daemon(self):
        """
        Run agent daemon
        """
        set_daemon_version(AGENT_VERSION)
        logger.set_prefix("Daemon")
        threading.current_thread().setName("Daemon")
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

    def run_exthandlers(self, debug=False):
        """
        Run the update and extension handler
        """
        logger.set_prefix("ExtHandler")
        threading.current_thread().setName("ExtHandler")

        #
        # Agents < 2.2.53 used to echo the log to the console. Since the extension handler could have been started by
        # one of those daemons, output a message indicating that output to the console will stop, otherwise users
        # may think that the agent died if they noticed that output to the console stops abruptly.
        #
        # Feel free to remove this code if telemetry shows there are no more agents <= 2.2.53 in the field.
        #
        if conf.get_logs_console() and get_daemon_version() < FlexibleVersion("2.2.53"):
            self.__add_console_appender(logger.LogLevel.INFO)
            try:
                logger.info(u"The agent will now check for updates and then will process extensions. Output to /dev/console will be suspended during those operations.")
            finally:
                logger.disable_console_output()

        from azurelinuxagent.ga.update import get_update_handler
        update_handler = get_update_handler()
        update_handler.run(debug)

    def show_configuration(self):
        configuration = conf.get_configuration()
        for k in sorted(configuration.keys()):
            print("{0} = {1}".format(k, configuration[k]))

    def collect_logs(self, is_full_mode):
        if is_full_mode:
            print("Running log collector mode full")
        else:
            print("Running log collector mode normal")

        try:
            log_collector = LogCollector(is_full_mode)
            archive = log_collector.collect_logs_and_get_archive()
            print("Log collection successfully completed. Archive can be found at {0} "
                  "and detailed log output can be found at {1}".format(archive, OUTPUT_RESULTS_FILE_PATH))
        except Exception as e: # pylint: disable=C0103
            print("Log collection completed unsuccessfully. Error: {0}".format(ustr(e)))
            print("Detailed log output can be found at {0}".format(OUTPUT_RESULTS_FILE_PATH))
            sys.exit(1)


def main(args=[]): # pylint: disable=R0912,W0102
    """
    Parse command line arguments, exit with usage() on error.
    Invoke different methods according to different command
    """
    if len(args) <= 0: # pylint: disable=len-as-condition
        args = sys.argv[1:]
    command, force, verbose, debug, conf_file_path, log_collector_full_mode = parse_args(args)
    if command == "version":
        version()
    elif command == "help":
        print(usage())
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
                agent.run_exthandlers(debug)
            elif command == "show-configuration":
                agent.show_configuration()
            elif command == "collect-logs":
                agent.collect_logs(log_collector_full_mode)
        except Exception:
            logger.error(u"Failed to run '{0}': {1}",
                         command,
                         traceback.format_exc())


def parse_args(sys_args): # pylint: disable=R0912
    """
    Parse command line arguments
    """
    cmd = "help"
    force = False
    verbose = False
    debug = False
    conf_file_path = None
    log_collector_full_mode = False

    for arg in sys_args:
        m = re.match("^(?:[-/]*)configuration-path:([\w/\.\-_]+)", arg) # pylint: disable=W1401,C0103
        if not m is None:
            conf_file_path = m.group(1)
            if not os.path.exists(conf_file_path):
                print("Error: Configuration file {0} does not exist".format(
                        conf_file_path), file=sys.stderr) 
                print(usage())
                sys.exit(1)
        elif re.match("^([-/]*)deprovision\\+user", arg):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", arg):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", arg):
            cmd = "daemon"
        elif re.match("^([-/]*)start", arg):
            cmd = "start"
        elif re.match("^([-/]*)register-service", arg):
            cmd = "register-service"
        elif re.match("^([-/]*)run-exthandlers", arg):
            cmd = "run-exthandlers"
        elif re.match("^([-/]*)version", arg):
            cmd = "version"
        elif re.match("^([-/]*)verbose", arg):
            verbose = True
        elif re.match("^([-/]*)debug", arg):
            debug = True
        elif re.match("^([-/]*)force", arg):
            force = True
        elif re.match("^([-/]*)show-configuration", arg):
            cmd = "show-configuration"
        elif re.match("^([-/]*)(help|usage|\\?)", arg):
            cmd = "help"
        elif re.match("^([-/]*)collect-logs", arg):
            cmd = "collect-logs"
        elif re.match("^([-/]*)full", arg):
            log_collector_full_mode = True
        else:
            cmd = "help"
            break

    return cmd, force, verbose, debug, conf_file_path, log_collector_full_mode


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
    Return agent usage message
    """
    s  = "\n" # pylint: disable=C0103
    s += ("usage: {0} [-verbose] [-force] [-help] " # pylint: disable=C0103
           "-configuration-path:<path to configuration file>" 
           "-deprovision[+user]|-register-service|-version|-daemon|-start|"
           "-run-exthandlers|-show-configuration|-collect-logs [-full]"
           "").format(sys.argv[0])
    s += "\n" # pylint: disable=C0103
    return s


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
