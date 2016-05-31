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

import os
import azurelinuxagent.conf as conf
import azurelinuxagent.logger as logger
import azurelinuxagent.event as event


class InitHandler(object):
    def __init__(self, distro):
        self.distro = distro

    def run(self, verbose):
        #Init stdout log
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.STDOUT, level)

        #Init config
        conf_file_path = self.distro.osutil.get_agent_conf_file_path()
        conf.load_conf_from_file(conf_file_path)

        #Init log
        verbose = verbose or conf.get_logs_verbose()
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.FILE, level,
                                 path="/var/log/waagent.log")
        logger.add_logger_appender(logger.AppenderType.CONSOLE, level,
                                 path="/dev/console")

        #Init event reporter
        event_dir = os.path.join(conf.get_lib_dir(), "events")
        event.init_event_logger(event_dir)
        event.enable_unhandled_err_dump("WALA")



