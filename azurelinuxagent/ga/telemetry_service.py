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
import datetime
import threading
import time
import traceback

from azurelinuxagent.common import logger
from azurelinuxagent.common.event import add_event, WALAEventOperation
from azurelinuxagent.common.exception import ServiceStoppedError
from azurelinuxagent.common.future import ustr, Queue
from azurelinuxagent.common.interfaces import ThreadHandlerInterface


def get_telemetry_service_handler(protocol_util):
    return TelemetryServiceHandler(protocol_util)


class TelemetryServiceHandler(ThreadHandlerInterface):
    """
    This Handler takes care of sending all telemetry out of the agent to Wireserver. It sends out data as soon as
    there's any data available in the queue to send.
    """

    _THREAD_NAME = "TelemetryServiceHandler"
    _MAX_TIMEOUT = datetime.timedelta(minutes=5).seconds
    _MIN_QUEUE_LIMIT = 30
    _MIN_WAIT_TIME = datetime.timedelta(seconds=5)


    def __init__(self, protocol_util):
        self._protocol = protocol_util.get_protocol()
        self.should_run = True
        self._thread = None
        self._should_process_events = threading.Event()
        self._queue = Queue() #PriorityQueue()

    @staticmethod
    def get_thread_name():
        return TelemetryServiceHandler._THREAD_NAME

    def run(self):
        logger.info("Start Extension Telemetry service.")
        self.start()

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        self._thread = threading.Thread(target=self._process_telemetry_thread)
        self._thread.setDaemon(True)
        self._thread.setName(self.get_thread_name())
        self._thread.start()

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.should_run = False
        # Set the event to unblock the thread to ensure that the thread is not blocking shutdown.
        self._should_process_events.set()
        if self.is_alive():
            self.join()

    def join(self):
        self._queue.join()
        self._thread.join()

    def stopped(self):
        return not self.should_run

    def enqueue_event(self, event):
        # Add event to queue and set event
        if self.stopped():
            raise ServiceStoppedError("{0} is stopped, not accepting anymore events".format(self.get_thread_name()))

        self._queue.put(event)

        # Set the event if any enqueue happens (even if already set) to trigger sending those events
        self._should_process_events.set()

    def _process_telemetry_thread(self):
        logger.info("Successfully started the {0} thread".format(self.get_thread_name()))
        try:
            # On demand wait, start processing as soon as there is any data available in the queue
            # In worst case, also keep checking every 5 mins to ensure that no data is being missed
            while not self.stopped():
                self._should_process_events.wait(timeout=TelemetryServiceHandler._MAX_TIMEOUT)
                self._send_events_in_queue()

        except Exception as error:
            err_msg = "An unknown error occurred in the {0} thread main loop, stopping thread. Error: {1}, Stack: {2}".format(
                self.get_thread_name(), ustr(error), traceback.format_exc())
            add_event(op=WALAEventOperation.UnhandledError, message=err_msg, is_success=False)

    def _get_events_in_queue(self):
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                yield event
            except Exception as error:
                logger.error("Some exception when fetching event from queue: {0}, {1}".format(ustr(error),
                                                                                              traceback.format_exc()))
            finally:
                self._queue.task_done()

    def _send_events_in_queue(self):
        # Process everything in Queue
        if not self._queue.empty():
            start_time = datetime.datetime.utcnow()
            while self._queue.qsize() < self._MIN_QUEUE_LIMIT or \
                    (start_time + self._MIN_WAIT_TIME) <= datetime.datetime.utcnow():
                # To promote batching, we either wait for atleast 30 events or 5 secs before sending out the first
                # request to wireserver
                time.sleep(secs=1)
            self._protocol.report_event(self._get_events_in_queue)

        # Reset the event when done processing all events in queue
        if self._should_process_events.is_set() and self._queue.empty():
            logger.verbose("Resetting the event")
            self._should_process_events.clear()