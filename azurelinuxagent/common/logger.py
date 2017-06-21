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
"""
Log utils
"""
import os
import sys
from azurelinuxagent.common.future import ustr
from datetime import datetime, timedelta

EVERY_DAY = timedelta(days=1)
EVERY_HALF_DAY = timedelta(hours=12)
EVERY_HOUR = timedelta(hours=1)
EVERY_HALF_HOUR = timedelta(minutes=30)
EVERY_FIFTEEN_MINUTES = timedelta(minutes=15)

class Logger(object):
    """
    Logger class
    """
    def __init__(self, logger=None, prefix=None):
        self.appenders = []
        self.logger = self if logger is None else logger
        self.periodic_messages = {}
        self.prefix = prefix

    def reset_periodic(self):
        self.logger.periodic_messages = {}

    def is_period_elapsed(self, delta, h):
        return h not in self.logger.periodic_messages or \
            (self.logger.periodic_messages[h] + delta) <= datetime.now()

    def periodic(self, delta, msg_format, *args):
        h = hash(msg_format)
        if self.is_period_elapsed(delta, h):
            self.info(msg_format, *args)
            self.logger.periodic_messages[h] = datetime.now()

    def verbose(self, msg_format, *args):
        self.log(LogLevel.VERBOSE, msg_format, *args)

    def info(self, msg_format, *args):
        self.log(LogLevel.INFO, msg_format, *args)

    def warn(self, msg_format, *args):
        self.log(LogLevel.WARNING, msg_format, *args)

    def error(self, msg_format, *args):
        self.log(LogLevel.ERROR, msg_format, *args)

    def log(self, level, msg_format, *args):
        #if msg_format is not unicode convert it to unicode
        if type(msg_format) is not ustr:
            msg_format = ustr(msg_format, errors="backslashreplace")
        if len(args) > 0:
            msg = msg_format.format(*args)
        else:
            msg = msg_format
        time = datetime.now().strftime(u'%Y/%m/%d %H:%M:%S.%f')
        level_str = LogLevel.STRINGS[level]
        if self.prefix is not None:
            log_item = u"{0} {1} {2} {3}\n".format(time, level_str, self.prefix,
                                                   msg)
        else:
            log_item = u"{0} {1} {2}\n".format(time, level_str, msg)

        log_item = ustr(log_item.encode('ascii', "backslashreplace"), 
                        encoding="ascii")

        for appender in self.appenders:
            appender.write(level, log_item)
        if self.logger != self:
            for appender in self.logger.appenders:
                appender.write(level, log_item)

    def add_appender(self, appender_type, level, path):
        appender = _create_logger_appender(appender_type, level, path)
        self.appenders.append(appender)

class ConsoleAppender(object):
    def __init__(self, level, path):
        self.level = level
        self.path = path

    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "w") as console:
                    console.write(msg)
            except IOError:
                pass

class FileAppender(object):
    def __init__(self, level, path):
        self.level = level
        self.path = path

    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "a+") as log_file:
                    log_file.write(msg)
            except IOError:
                pass

class StdoutAppender(object):
    def __init__(self, level):
        self.level = level

    def write(self, level, msg):
        if self.level <= level:
            try:
                sys.stdout.write(msg)
            except IOError:
                pass

#Initialize logger instance
DEFAULT_LOGGER = Logger()

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
    FILE = 0
    CONSOLE = 1
    STDOUT = 2

def add_logger_appender(appender_type, level=LogLevel.INFO, path=None):
    DEFAULT_LOGGER.add_appender(appender_type, level, path)

def reset_periodic():
    DEFAULT_LOGGER.reset_periodic()

def periodic(delta, msg_format, *args):
    DEFAULT_LOGGER.periodic(delta, msg_format, *args)

def verbose(msg_format, *args):
    DEFAULT_LOGGER.verbose(msg_format, *args)

def info(msg_format, *args):
    DEFAULT_LOGGER.info(msg_format, *args)

def warn(msg_format, *args):
    DEFAULT_LOGGER.warn(msg_format, *args)

def error(msg_format, *args):
    DEFAULT_LOGGER.error(msg_format, *args)

def log(level, msg_format, *args):
    DEFAULT_LOGGER.log(level, msg_format, args)

def _create_logger_appender(appender_type, level=LogLevel.INFO, path=None):
    if appender_type == AppenderType.CONSOLE:
        return ConsoleAppender(level, path)
    elif appender_type == AppenderType.FILE:
        return FileAppender(level, path)
    elif appender_type == AppenderType.STDOUT:
        return StdoutAppender(level)
    else:
        raise ValueError("Unknown appender type")

