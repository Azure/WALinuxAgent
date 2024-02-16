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
# This script starts the actual agent and then launches an instance of the dummy process periodically to consume the CPU
#
import signal
import subprocess
import sys
import threading
import time
import traceback

from azurelinuxagent.common import logger


class CpuConsumer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self._stopped = False

    def run(self):
        threading.current_thread().setName("*Stress*")  # pylint: disable=deprecated-method

        while not self._stopped:
            try:
                # Dummy operation(reads empty streams and drops) which creates load on the CPU
                dd_command = ["dd", "if=/dev/zero", "of=/dev/null"]
                logger.info("Starting dummy dd command: {0} to stress CPU", ' '.join(dd_command))
                subprocess.Popen(dd_command)
                logger.info("dd command completed; sleeping...")
                i = 0
                while i < 30 and not self._stopped:
                    time.sleep(1)
                    i += 1
            except Exception as run_exception:
                logger.error("{0}:\n{1}", run_exception, traceback.format_exc())

    def stop(self):
        self._stopped = True


try:
    threading.current_thread().setName("*StartService*")  # pylint: disable=deprecated-method
    logger.set_prefix("E2ETest")
    logger.add_logger_appender(logger.AppenderType.FILE, logger.LogLevel.INFO, "/var/log/waagent.log")

    agent_command_line = sys.argv[1:]

    logger.info("Starting Agent: {0}", ' '.join(agent_command_line))
    agent_process = subprocess.Popen(agent_command_line)

    # sleep a little to give the agent a chance to initialize
    time.sleep(15)

    cpu_consumer = CpuConsumer()
    cpu_consumer.start()


    def forward_signal(signum, _):
        if signum == signal.SIGTERM:
            logger.info("Stopping stress thread...")
            cpu_consumer.stop()
            logger.info("Forwarding signal {0} to Agent", signum)
            agent_process.send_signal(signum)


    signal.signal(signal.SIGTERM, forward_signal)

    agent_process.wait()
    logger.info("Agent completed")

    cpu_consumer.stop()
    cpu_consumer.join()
    logger.info("Stress completed")

    logger.info("Exiting...")
    sys.exit(agent_process.returncode)

except Exception as exception:
    logger.error("Unexpected error occurred while starting agent service : {0}", exception)
    raise
