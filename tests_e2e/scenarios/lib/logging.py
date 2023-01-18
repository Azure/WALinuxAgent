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

#
# This module defines a single object, 'log', of type AgentLogger, which the end-to-end tests and libraries use
# for logging.
#

from logging import FileHandler, Formatter, Handler, Logger, StreamHandler, INFO
from pathlib import  Path
from threading import current_thread
from typing import Dict, Callable


class _AgentLoggingHandler(Handler):
    """
    AgentLoggingHandler is a helper class for AgentLogger.

    This handler simply redirects logging to other handlers. It maintains a set of FileHandlers associated to specific
    threads. When a thread emits a log record, the AgentLoggingHandler passes through the call to the FileHandlers
    associated with that thread, or to a StreamHandler that outputs to stdout if there is not a FileHandler for that
    thread.

    Thread can set a FileHandler for themselves using _AgentLoggingHandler.set_current_thread_log() and remove that
    handler using _AgentLoggingHandler.close_current_thread_log().

    The _AgentLoggingHandler simply passes through calls to setLevel, setFormatter, flush, and close to the handlers
    it maintains.

    AgentLoggingHandler is meant to be primarily used in multithreaded scenarios and is thread-safe.
    """
    def __init__(self):
        super().__init__()
        self.formatter: Formatter = Formatter('%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%SZ")
        self.default_handler = StreamHandler()
        self.default_handler.setFormatter(self.formatter)
        self.per_thread_handlers: Dict[int, FileHandler] = {}

    def set_thread_log(self, thread_ident: int, log_file: Path) -> None:
        self.close_current_thread_log()
        handler: FileHandler = FileHandler(str(log_file))
        handler.setFormatter(self.formatter)
        self.per_thread_handlers[thread_ident] = handler

    def close_thread_log(self, thread_ident: int) -> None:
        handler = self.per_thread_handlers.pop(thread_ident, None)
        if handler is not None:
            handler.close()

    def set_current_thread_log(self, log_file: Path) -> None:
        self.set_thread_log(current_thread().ident, log_file)

    def close_current_thread_log(self) -> None:
        self.close_thread_log(current_thread().ident)

    def emit(self, record) -> None:
        handler = self.per_thread_handlers.get(current_thread().ident)
        if handler is None:
            handler = self.default_handler
        handler.emit(record)

    def setLevel(self, level) -> None:
        self._for_each_handler(lambda h: h.setLevel(level))

    def setFormatter(self, fmt) -> None:
        self._for_each_handler(lambda h: h.setFormatter(fmt))

    def flush(self) -> None:
        self._for_each_handler(lambda h: h.flush())

    def close(self) -> None:
        self._for_each_handler(lambda h: h.close())

    def _for_each_handler(self, op: Callable[[Handler], None]) -> None:
        op(self.default_handler)
        # copy of the values into a new list in case the dictionary changes while we are iterating
        for handler in list(self.per_thread_handlers.values()):
            op(handler)


class AgentLogger(Logger):
    """
    AgentLogger is a Logger customized for agent test scenarios. When tests are executed from the command line
    (for example, during development) the AgentLogger can be used with its default configuration, which simply
    outputs to stdout. When tests are executed from the test framework, typically there are multiple test suites
    executed concurrently on different threads, and each test suite must have its own log file; in that case,
    each thread can call AgentLogger.set_current_thread_log() to send all the logging from that thread to a
    particular file.
    """
    def __init__(self):
        super().__init__(name="waagent", level=INFO)
        self._handler: _AgentLoggingHandler = _AgentLoggingHandler()
        self.addHandler(self._handler)

    def set_thread_log(self, thread_ident: int, log_file: Path) -> None:
        self._handler.set_thread_log(thread_ident, log_file)

    def close_thread_log(self, thread_ident: int) -> None:
        self._handler.close_thread_log(thread_ident)

    def set_current_thread_log(self, log_file: Path) -> None:
        self._handler.set_current_thread_log(log_file)

    def close_current_thread_log(self) -> None:
        self._handler.close_current_thread_log()


log: AgentLogger = AgentLogger()

