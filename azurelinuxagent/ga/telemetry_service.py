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

from azurelinuxagent.common import logger
from azurelinuxagent.common.future import ustr, PriorityQueue


def get_telemetry_service_handler(protocol_util):
    return TelemetryServiceHandler(protocol_util)

class TelemetryServiceHandler(object):
    """
    This Handler takes care of sending all telemetry out of the agent to Wireserver. It sends out data as soon as
    there's any data available in the queue to send.
    """

    _THREAD_NAME = "TelemetryServiceHandler"
    _MAX_TIMEOUT = datetime.timedelta(minutes=5).seconds

    def __init__(self, protocol_util):
        self._protocol = protocol_util.get_protocol()
        self.should_run = True
        self.thread = None
        self._should_process_events = threading.Event()
        self._queue = PriorityQueue()

    @staticmethod
    def get_thread_name():
        return TelemetryServiceHandler._THREAD_NAME

    def run(self):
        logger.info("Start Extension Telemetry service.")
        self.start()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        self.thread = threading.Thread(target=self.daemon)
        self.thread.setDaemon(True)
        self.thread.setName(self.get_thread_name())
        self.thread.start()

    def stop(self):
        """
        Stop server communication and join the thread to main thread.
        """
        self.should_run = False
        if self.is_alive():
            self.thread.join()

    def stopped(self):
        return not self.should_run

    def enqueue_event(self, event, priority):
        # Add event to queue and set event
        self._queue.put((priority, event))

        # Always set the event if any enqueue happens (even if already set)
        self._should_process_events.set()

    def daemon(self):
        logger.info("Successfully started the {0} thread".format(self.get_thread_name()))
        try:
            # On demand wait, start processing as soon as there is any data available in the queue
            # In worst case, also keep checking every 5 mins to ensure that no data is being missed
            while self._should_process_events.wait(timeout=TelemetryServiceHandler._MAX_TIMEOUT):
                self.send_events_in_queue()

        except Exception as error:
            logger.warn("An unknown error occurred in the {0} thread main loop, stopping thread. Error: {1}",
                        self.get_thread_name(), ustr(error))

    def get_events(self):
        while not self._queue.empty():
            try:
                _, event = self._queue.get()
                yield event
            finally:
                # Mark the event as processed once done
                self._queue.task_done()

    def send_events_in_queue(self):
        # Process everything in Queue
        if not self._queue.empty():
            self._protocol.report_event(self.get_events)

        # Clear event when done
        # There might be a rare race condition where the loop exits and we get a new event, in that case not unsetting the event.
        if self._should_process_events.is_set() and not self._queue.empty():
            self._should_process_events.clear()