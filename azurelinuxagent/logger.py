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

import sys
import traceback
import azurelinuxagent.utils.textutil as textutil
from datetime import datetime

class Logger(object):
    def __init__(self, logger=None, prefix=None):
        self.appenders = []
        if logger is not None:
            self.appenders.extend(logger.appenders)
        self.prefix = prefix

    def verbose(self, msg_format, *args):
        self.log(LogLevel.VERBOSE, msg_format, *args)

    def info(self, msg_format, *args):
        self.log(LogLevel.INFO, msg_format, *args)

    def warn(self, msg_format, *args):
        self.log(LogLevel.WARNING, msg_format, *args)

    def error(self, msg_format, *args):
        self.log(LogLevel.ERROR, msg_format, *args)

    def log(self, level, msg_format, *args):
        msg_format = textutil.Ascii(msg_format) 
        args = map(lambda x : textutil.Ascii(x), args)
        if(len(args) > 0):
            msg = msg_format.format(*args)
        else:
            msg = msg_format
        time = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        levelStr = LogLevel.STRINGS[level]
        if self.prefix is not None:
            logItem = "{0} {1} {2} {3}".format(time, levelStr, self.prefix, msg)
        else:
            logItem = "{0} {1} {2}".format(time, levelStr, msg)
        for appender in self.appenders:
            appender.write(level, logItem)

    def addLoggerAppender(self, appenderType, level, path):
        appender = CreateLoggerAppender(appenderType, level, path)
        self.appenders.append(appender)

class ConsoleAppender(object):
    def __init__(self, level, path):
        self.level = LogLevel.INFO
        if level >= LogLevel.INFO:
            self.level = level
        self.path = path
       
    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "w") as console :
                    console.write(msg.encode('ascii','ignore') + "\n")
            except IOError as e:
                pass
            
class FileAppender(object):
    def __init__(self, level, path):
        self.level = level
        self.path = path

    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "a+") as log_file:
                    log_file.write(msg.encode('ascii','ignore') + "\n")
            except IOError as e:
                pass

class StdoutAppender(object):
    def __init__(self, level):
        self.level = level

    def write(self, level, msg):
        if self.level <= level:
            try:
                sys.stdout.write(msg.encode('ascii','ignore') + "\n")
            except IOError as e:
                pass


#Initialize logger instance
DefaultLogger = Logger()

class LogLevel(object):
    VERBOSE = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    STRINGS = [
        "VERBOSE",
        "INFO",
        "WARNING",
        "ERROR"
    ]

class AppenderType(object):
    FILE=0
    CONSOLE=1
    STDOUT=2

def AddLoggerAppender(appenderType, level=LogLevel.INFO, path=None):
    DefaultLogger.addLoggerAppender(appenderType, level, path)

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

def CreateLoggerAppender(appenderType, level=LogLevel.INFO, path=None):
    if appenderType == AppenderType.CONSOLE :
        return ConsoleAppender(level, path)
    elif appenderType == AppenderType.FILE :
        return FileAppender(level, path)
    elif appenderType == AppenderType.STDOUT :
        return StdoutAppender(level)
    else:
        raise ValueError("Unknown appender type")

def LogError(operation):
    def Decorator(func):
        def Wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs) 
            except Exception, e:
                Error("Failed to {0} :{1} {2}", 
                      operation, 
                      e, 
                      traceback.format_exc()) 
                raise e
            return result
        return Wrapper
    return Decorator
