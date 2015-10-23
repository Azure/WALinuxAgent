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
from azurelinuxagent.utils.osutil import OSUTIL
import azurelinuxagent.utils.fileutil as fileutil


class InitHandler(object):
    def init(self, verbose):
        #Init stdout log
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.STDOUT, level)

        #Init config
        conf_file_path = OSUTIL.get_conf_file_path()
        conf.load_conf(conf_file_path)

        #Init log
        verbose = verbose or conf.get_switch("Logs.Verbose", False)
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.FILE, level,
                                 path="/var/log/waagent.log")
        logger.add_logger_appender(logger.AppenderType.CONSOLE, level,
                                 path="/dev/console")

        #Create lib dir
        fileutil.mkdir(OSUTIL.get_lib_dir(), mode=0o700)
        os.chdir(OSUTIL.get_lib_dir())


