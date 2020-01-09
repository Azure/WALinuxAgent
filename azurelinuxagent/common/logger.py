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
# Requires Python 2.6+ and openssl_bin 1.0+
#
"""
Log utils
"""
import sys
from datetime import datetime, timedelta

from azurelinuxagent.common.future import ustr

EVERY_DAY = timedelta(days=1)
EVERY_HALF_DAY = timedelta(hours=12)
EVERY_SIX_HOURS = timedelta(hours=6)
EVERY_HOUR = timedelta(hours=1)
EVERY_HALF_HOUR = timedelta(minutes=30)
EVERY_FIFTEEN_MINUTES = timedelta(minutes=15)
EVERY_MINUTE = timedelta(minutes=1)


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

    def set_prefix(self, prefix):
        self.prefix = prefix

    def _is_period_elapsed(self, delta, h):
        return h not in self.logger.periodic_messages or \
            (self.logger.periodic_messages[h] + delta) <= datetime.now()

    def _periodic(self, delta, log_level_op, msg_format, *args):
        h = hash(msg_format)
        if self._is_period_elapsed(delta, h):
            log_level_op(msg_format, *args)
            self.logger.periodic_messages[h] = datetime.now()

    def periodic_info(self, delta, msg_format, *args):
        self._periodic(delta, self.info, msg_format, *args)

    def periodic_verbose(self, delta, msg_format, *args):
        self._periodic(delta, self.verbose, msg_format, *args)

    def periodic_warn(self, delta, msg_format, *args):
        self._periodic(delta, self.warn, msg_format, *args)

    def periodic_error(self, delta, msg_format, *args):
        self._periodic(delta, self.error, msg_format, *args)

    def verbose(self, msg_format, *args):
        self.log(LogLevel.VERBOSE, msg_format, *args)

    def info(self, msg_format, *args):
        self.log(LogLevel.INFO, msg_format, *args)

    def warn(self, msg_format, *args):
        self.log(LogLevel.WARNING, msg_format, *args)

    def error(self, msg_format, *args):
        self.log(LogLevel.ERROR, msg_format, *args)

    def log(self, level, msg_format, *args):
        def write_log(log_appender):
            """
            The appender_lock flag is used to signal if the logger is currently in use. This prevents a subsequent log
            coming in due to writing of a log statement to be not written.

            Eg:
            Assuming a logger with two appenders - FileAppender and TelemetryAppender. Here is an example of
            how using appender_lock flag can help.

            logger.warn("foo")
                |- log.warn() (azurelinuxagent.common.logger.Logger.warn)
                    |- log() (azurelinuxagent.common.logger.Logger.log)
                        |- FileAppender.appender_lock is currently False not log_appender.appender_lock is True
                            |- We sets it to True.
                        |- FileAppender.write completes.
                        |- FileAppender.appender_lock sets to False.
                        |- TelemetryAppender.appender_lock is currently False not log_appender.appender_lock is True
                            |- We sets it to True.
                    [A] |- TelemetryAppender.write gets called but has an error and writes a log.warn("bar")
                            |- log() (azurelinuxagent.common.logger.Logger.log)
                            |- FileAppender.appender_lock is set to True (log_appender.appender_lock was false when entering).
                            |- FileAppender.write completes.
                            |- FileAppender.appender_lock sets to False.
                            |- TelemetryAppender.appender_lock is already True, not log_appender.appender_lock is False
                            Thus [A] cannot happen again if TelemetryAppender.write is not getting called. It prevents
                            faulty appenders to not get called again and again.

            :param log_appender: Appender
            :return: None
            """
            if not log_appender.appender_lock:
                try:
                    log_appender.appender_lock = True
                    log_appender.write(level, log_item)
                finally:
                    log_appender.appender_lock = False

        # if msg_format is not unicode convert it to unicode
        if type(msg_format) is not ustr:
            msg_format = ustr(msg_format, errors="backslashreplace")
        if len(args) > 0:
            msg = msg_format.format(*args)
        else:
            msg = msg_format
            # This format is based on ISO-8601, Z represents UTC (Zero offset)
        time = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
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
            #
            # TODO: we should actually call
            #
            #     write_log(appender)
            #
            # (see PR #1659). Before doing that, write_log needs to be thread-safe.
            #
            # This needs to be done when SEND_LOGS_TO_TELEMETRY is enabled.
            #

        if self.logger != self:
            for appender in self.logger.appenders:
                appender.write(level, log_item)
                #
                # TODO: call write_log instead (see comment above)
                #

    def add_appender(self, appender_type, level, path):
        appender = _create_logger_appender(appender_type, level, path)
        self.appenders.append(appender)


class Appender(object):
    def __init__(self, level):
        self.appender_lock = False
        self.level = level

    def write(self, level, msg):
        pass


class ConsoleAppender(Appender):
    def __init__(self, level, path):
        super(ConsoleAppender, self).__init__(level)
        self.path = path

    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "w") as console:
                    console.write(msg)
            except IOError:
                pass


class FileAppender(Appender):
    def __init__(self, level, path):
        super(FileAppender, self).__init__(level)
        self.path = path

    def write(self, level, msg):
        if self.level <= level:
            try:
                with open(self.path, "a+") as log_file:
                    log_file.write(msg)
            except IOError:
                pass


class StdoutAppender(Appender):
    def __init__(self, level):
        super(StdoutAppender, self).__init__(level)

    def write(self, level, msg):
        if self.level <= level:
            try:
                sys.stdout.write(msg)
            except IOError:
                pass


class TelemetryAppender(Appender):
    def __init__(self, level, event_func):
        super(TelemetryAppender, self).__init__(level)
        self.event_func = event_func

    def write(self, level, msg):
        if self.level <= level:
            try:
                self.event_func(level, msg)
            except IOError:
                pass


# Initialize logger instance
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
    TELEMETRY = 3


def add_logger_appender(appender_type, level=LogLevel.INFO, path=None):
    DEFAULT_LOGGER.add_appender(appender_type, level, path)


def reset_periodic():
    DEFAULT_LOGGER.reset_periodic()


def set_prefix(prefix):
    DEFAULT_LOGGER.set_prefix(prefix)


def periodic_info(delta, msg_format, *args):
    """
    The hash-map maintaining the state of the logs gets reset here -
    azurelinuxagent.ga.monitor.MonitorHandler.reset_loggers. The current time period is defined by RESET_LOGGERS_PERIOD.
    """
    DEFAULT_LOGGER.periodic_info(delta, msg_format, *args)


def periodic_verbose(delta, msg_format, *args):
    """
    The hash-map maintaining the state of the logs gets reset here -
    azurelinuxagent.ga.monitor.MonitorHandler.reset_loggers. The current time period is defined by RESET_LOGGERS_PERIOD.
    """
    DEFAULT_LOGGER.periodic_verbose(delta, msg_format, *args)


def periodic_error(delta, msg_format, *args):
    """
    The hash-map maintaining the state of the logs gets reset here -
    azurelinuxagent.ga.monitor.MonitorHandler.reset_loggers. The current time period is defined by RESET_LOGGERS_PERIOD.
    """
    DEFAULT_LOGGER.periodic_error(delta, msg_format, *args)


def periodic_warn(delta, msg_format, *args):
    """
    The hash-map maintaining the state of the logs gets reset here -
    azurelinuxagent.ga.monitor.MonitorHandler.reset_loggers. The current time period is defined by RESET_LOGGERS_PERIOD.
    """
    DEFAULT_LOGGER.periodic_warn(delta, msg_format, *args)


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
    elif appender_type == AppenderType.TELEMETRY:
        return TelemetryAppender(level, path)
    else:
        raise ValueError("Unknown appender type")

