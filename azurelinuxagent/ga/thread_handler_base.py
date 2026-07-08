# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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

import threading


class ThreadHandlerBase(object):
    """
    Abstract base class for all thread handlers.

    Lifecycle (mirrors threading):

        handler.start()                          # launch the worker thread
        ...
        handler.stop()                           # signal the thread to exit; non-blocking; idempotent
        handler.join(timeout=...)                # wait up to 'timeout' seconds for it to actually exit
        handler.is_alive()                       # True until the thread has exited

    To stop a handler completely, callers do:    handler.stop(); handler.join()
    Separating the two lets a shutdown sequence broadcast stop() to many handlers and then join them in
    parallel, instead of serializing each handler's join timeout.

    Subclasses only need to implement get_thread_name() and daemon() (the thread body). The base class
    provides everything else.

    Daemon loops should:
      * Use `while not self.stopped()` (or include `self.stopped()` in their exit condition) so they exit
        promptly when stop() is called.
      * Use self._sleep(seconds) instead of time.sleep(seconds), so they wake up immediately when stop()
        is called, instead of sleeping through the shutdown window.
      * Use self._run_periodic_operations(ops) instead of a plain for-loop over ops, so they stop the
        iteration as soon as stop() is called (rather than running every remaining operation first).
    """

    # Default timeout in seconds to wait for the thread to exit when join() is called without an explicit timeout
    _THREAD_JOIN_TIMEOUT = 5

    def __init__(self):
        # Set when stop() is called; checked by stopped() and waited on by self._sleep().
        self._stop_event = threading.Event()
        # The underlying daemon thread; created in start(), checked in is_alive(), waited on in join().
        self._thread = None

    # ----- helpers for daemon() implementations -----

    def _sleep(self, timeout):
        """
        Blocks for up to 'timeout' seconds, but returns early if another thread calls stop().
        """
        self._stop_event.wait(timeout)

    def _run_periodic_operations(self, periodic_operations):
        """
        Runs each operation in the given list, but bails out as soon as stop() has been called. This avoids
        starting a new periodic operation once shutdown has been signaled.
        """
        for op in periodic_operations:
            if self.stopped():
                break
            op.run()

    # ----- subclass contract -----

    @staticmethod
    def get_thread_name():
        raise NotImplementedError("get_thread_name() not implemented")

    def daemon(self):
        """
        The thread body. Subclasses MUST override this with their main logic.
        """
        raise NotImplementedError("daemon() not implemented")

    # ----- public lifecycle (provided by the base class) -----

    def run(self):
        """
        Default entry point: launches the worker thread. Subclasses may override to add a log message or
        restart-existing-thread logic before calling self.start().
        """
        self.start()

    def keep_alive(self):
        """
        Returns true if the handler should be restarted when the thread dies and false when it should remain
        dead. Defaults to True; subclasses may override.
        """
        return True

    def stopped(self):
        """
        True once stop() has been called. Daemon loops use this in `while not self.stopped()`.
        """
        return self._stop_event.is_set()

    def is_alive(self):
        """
        True until the worker thread has exited.
        """
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """
        Launches the daemon loop on a new background thread. Clears the stop event first, so a handler that
        was previously stopped can be cleanly restarted.
        """
        self._stop_event.clear()
        self._thread = threading.Thread(target=self.daemon)
        self._thread.daemon = True
        self._thread.name = self.get_thread_name()
        self._thread.start()

    def stop(self):
        """
        Signals the thread to exit. Non-blocking and idempotent: repeated calls have no additional effect.
        Use join() to wait for the thread to actually finish.
        """
        self._stop_event.set()

    def join(self, timeout=None):
        """
        Waits up to 'timeout' seconds for the thread to exit. If 'timeout' is None (the default),
        self._THREAD_JOIN_TIMEOUT is used; this is resolved at call time so that subclasses can
        override _THREAD_JOIN_TIMEOUT as a class attribute and have the override honored here.
        """
        if timeout is None:
            timeout = self._THREAD_JOIN_TIMEOUT
        if self._thread is not None:
            try:
                self._thread.join(timeout=timeout)
            except RuntimeError:
                pass

    def stop_and_join(self, timeout=None):
        """
        Convenience method: signals the thread to exit and waits for it to finish. Equivalent to:

            handler.stop()
            handler.join(timeout=timeout)
        """
        self.stop()
        self.join(timeout=timeout)

