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

import os
import sys
import time
import traceback

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.event import add_event, WALAEventOperation, initialize_event_logger_vminfo_common_parameters
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.rdma import setup_rdma_device
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_NAME, \
    AGENT_VERSION, \
    DISTRO_NAME, DISTRO_VERSION, PY_VERSION_MAJOR, PY_VERSION_MINOR, \
    PY_VERSION_MICRO
from azurelinuxagent.daemon.resourcedisk import get_resourcedisk_handler
from azurelinuxagent.daemon.scvmm import get_scvmm_handler
from azurelinuxagent.ga.update import get_update_handler
from azurelinuxagent.pa.provision import get_provision_handler
from azurelinuxagent.pa.rdma import get_rdma_handler

OPENSSL_FIPS_ENVIRONMENT = "OPENSSL_FIPS"


def get_daemon_handler():
    return DaemonHandler()


class DaemonHandler(object):
    """
    Main thread of daemon. It will invoke other threads to do actual work
    """

    def __init__(self):
        self.running = True
        self.osutil = get_osutil()

    def run(self, child_args=None):
        #
        # The Container ID in telemetry events is retrieved from the goal state. We can fetch the goal state
        # only after protocol detection, which is done during provisioning.
        #
        # Be aware that telemetry events emitted before that will not include the Container ID.
        #
        logger.info("{0} Version:{1}", AGENT_LONG_NAME, AGENT_VERSION)
        logger.info("OS: {0} {1}", DISTRO_NAME, DISTRO_VERSION)
        logger.info("Python: {0}.{1}.{2}", PY_VERSION_MAJOR, PY_VERSION_MINOR, PY_VERSION_MICRO)

        self.check_pid()
        self.initialize_environment()

        # If FIPS is enabled, set the OpenSSL environment variable
        # Note:
        # -- Subprocesses inherit the current environment
        if conf.get_fips_enabled():
            os.environ[OPENSSL_FIPS_ENVIRONMENT] = '1'

        while self.running:
            try:
                self.daemon(child_args)
            except Exception as e:  # pylint: disable=W0612
                err_msg = traceback.format_exc()
                add_event(name=AGENT_NAME, is_success=False, message=ustr(err_msg),
                          op=WALAEventOperation.UnhandledError)
                logger.warn("Daemon ended with exception -- Sleep 15 seconds and restart daemon")
                time.sleep(15)

    def check_pid(self):
        """Check whether daemon is already running"""
        pid = None
        pid_file = conf.get_agent_pid_file_path()
        if os.path.isfile(pid_file):
            pid = fileutil.read_file(pid_file)

        if self.osutil.check_pid_alive(pid):
            logger.info("Daemon is already running: {0}", pid)
            sys.exit(0)

        fileutil.write_file(pid_file, ustr(os.getpid()))

    def sleep_if_disabled(self):
        agent_disabled_file_path = conf.get_disable_agent_file_path()
        if os.path.exists(agent_disabled_file_path):
            import threading
            logger.warn("Disabling the guest agent by sleeping forever; "
                        "to re-enable, remove {0} and restart"
                        .format(agent_disabled_file_path))
            self.running = False
            disable_event = threading.Event()
            disable_event.wait()

    def initialize_environment(self):
        # Create lib dir
        if not os.path.isdir(conf.get_lib_dir()):
            fileutil.mkdir(conf.get_lib_dir(), mode=0o700)
            os.chdir(conf.get_lib_dir())

    def _initialize_telemetry(self):
        protocol = self.protocol_util.get_protocol()
        initialize_event_logger_vminfo_common_parameters(protocol)

    def daemon(self, child_args=None):
        logger.info("Run daemon")

        self.protocol_util = get_protocol_util()  # pylint: disable=W0201
        self.scvmm_handler = get_scvmm_handler()  # pylint: disable=W0201
        self.resourcedisk_handler = get_resourcedisk_handler()  # pylint: disable=W0201
        self.rdma_handler = get_rdma_handler()  # pylint: disable=W0201
        self.provision_handler = get_provision_handler()  # pylint: disable=W0201
        self.update_handler = get_update_handler()  # pylint: disable=W0201

        if conf.get_detect_scvmm_env():
            self.scvmm_handler.run()

        if conf.get_resourcedisk_format():
            self.resourcedisk_handler.run()

        # Always redetermine the protocol start (e.g., wireserver vs.
        # on-premise) since a VHD can move between environments
        self.protocol_util.clear_protocol()

        self.provision_handler.run()

        # Once we have the protocol, complete initialization of the telemetry fields
        # that require the goal state and IMDS
        self._initialize_telemetry()

        # Enable RDMA, continue in errors
        if conf.enable_rdma():
            nd_version = self.rdma_handler.get_rdma_version()
            self.rdma_handler.install_driver_if_needed()

            logger.info("RDMA capabilities are enabled in configuration")
            try:
                # Ensure the most recent SharedConfig is available
                # - Changes to RDMA state may not increment the goal state
                #   incarnation number. A forced update ensures the most
                #   current values.
                protocol = self.protocol_util.get_protocol()
                if type(protocol) is not WireProtocol:
                    raise Exception("Attempt to setup RDMA without Wireserver")

                protocol.client.update_goal_state(forced=True)

                setup_rdma_device(nd_version, protocol.client.get_shared_conf())
            except Exception as e:
                logger.error("Error setting up rdma device: %s" % e)
        else:
            logger.info("RDMA capabilities are not enabled, skipping")

        self.sleep_if_disabled()

        # Disable output to /dev/console once provisioning has completed
        if logger.console_output_enabled():
            logger.info("End of log to /dev/console. The agent will now check for updates and then will process extensions.")
            logger.disable_console_output()

        while self.running:
            self.update_handler.run_latest(child_args=child_args)
