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
# Requires Python 2.4+ and openssl_bin 1.0+
#
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import walinuxagent.utils.textutil as textutil
from datetime import datetime

LogFilePath = '/var/log/waagent.log'
ConsoleFilePath = '/dev/console'

class Logger(object):
    def __init__(self, logger=None):
        if logger is None:
            self.appenders = []
        else:
            self.appenders = logger.appenders

    def verbose(self, msg_format, *args):
        self.log("VERBOSE", msg_format, *args)

    def info(self, msg_format, *args):
        self.log("INFO", msg_format, *args)

    def warn(self, msg_format, *args):
        self.log("WARNING", msg_format, *args)

    def error(self, msg_format, *args):
        self.log("ERROR", msg_format, *args)

    def log(self, level, msg_format, *args):
        msg_format = textutil.Ascii(msg_format) 
        args = map(lambda x : textutil.Ascii(x), args)
        msg = msg_format.format(*args)
        time = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        logItem = "{0} {1} {2}".format(time, level, msg)
        for appender in self.appenders:
            appender.write(level, logItem)

    def addLoggerAppender(self, appender_config):
        appender = CreateLoggerAppender(appender_config)
        self.appenders.append(appender)

class AppenderConfig():
    def __init__(self, properties = {}):
        self.properties = properties

class ConsoleAppender():
    def __init__(self, appender_config):
        self.level = appender_config.properties['level']
        self.console_path = appender_config.properties['console_path']
        if not self.level:
            raise Exception("Log level is not specified.")
        if not self.console_path:
            raise Exception("Console path is not specified.")

    def write(self, level, msg):
        if _MatchLogLevel(self.level, level):
            with open(self.console_path, "w") as console :
                console.write(msg.encode('ascii','ignore') + "\n")
                console.close()
            
class FileAppender():
    def __init__(self, appender_config):
        self.level = appender_config.properties['level']
        self.file_path = appender_config.properties['file_path']
        if not self.level:
            raise Exception("Log level is not specified.")
        if not self.file_path:
            raise Exception("File path is not specified.")

    def write(self, level, msg):
        if _MatchLogLevel(self.level, level):
            with open(self.file_path, "a") as log_file:
                log_file.write(msg.encode('ascii','ignore') + "\n")
                log_file.close()

#Initialize logger instance
DefaultLogger = Logger()
__log_level = {"VERBOSE" : 0, "INFO": 1, "WARNING": 2, "ERROR" : 3}        

def _MatchLogLevel(expected, actual):
    return __log_level[actual] >= __log_level[expected]


def LoggerInit(log_file_path, log_console_path, 
               Verbose=False, logger=DefaultLogger):
    if log_file_path:
        file_appender_config = AppenderConfig({
            "type":"FILE", 
            "level" : "INFO", 
            "file_path" : log_file_path
        })
        
        #File appender will log Verbose log if the switch is on
        if Verbose: 
            file_appender_config.properties['level'] = "Verbose"
        logger.addLoggerAppender(file_appender_config)

    if log_console_path:
        console_appender_config = AppenderConfig({
            "type":"CONSOLE", 
            "level" : "INFO", 
            "console_path" : log_console_path
        })
        logger.addLoggerAppender(console_appender_config)

def AddLoggerAppender(appender_config):
    DefaultLogger.addLoggerAppender(appender_config)

def Verbose(msg_format, *args):
    DefaultLogger.verbose(msg_format, *args)

def Info(msg_format, *args):
    DefaultLogger.info(msg_format, *args)

def Warn(msg_format, *args):
    DefaultLogger.warn(msg_format, *args)

def Error(msg_format, *args):
    DefaultLogger.error(msg_format, *args)

def Log(level, msg_format, *args):
    DefaultLogger.log(level, msg_format, args)

def CreateLoggerAppender(appender_config):
    if appender_config.properties['type'] == 'CONSOLE' :
        return ConsoleAppender(appender_config)
    elif appender_config.properties['type'] == 'FILE' :
        return FileAppender(appender_config)
    else:
        raise Exception("Unknown appender type")

