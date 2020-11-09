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
from azurelinuxagent.common.future import ustr, Queue, Empty
from azurelinuxagent.common.interfaces import ThreadHandlerInterface


def get_send_telemetry_events_handler(protocol_util):
    return SendTelemetryEventsHandler(protocol_util)


class SendTelemetryEventsHandler(ThreadHandlerInterface):
    """
    This Handler takes care of sending all telemetry out of the agent to Wireserver. It sends out data as soon as
    there's any data available in the queue to send.
    """

    _THREAD_NAME = "SendTelemetryHandler"
    _MAX_TIMEOUT = datetime.timedelta(seconds=5).seconds
    _MIN_EVENTS_TO_BATCH = 30
    _MIN_BATCH_WAIT_TIME = datetime.timedelta(seconds=5)


    def __init__(self, protocol_util):
        self._protocol = protocol_util.get_protocol()
        self.should_run = True
        self._thread = None

        # We're using a Queue for handling the communication between threads. We plan to remove any dependency on the
        # filesystem in the future and use add_event to directly queue events into the queue rather than writing to
        # a file and then parsing it later.

        # Once we move add_event to directly queue events, we need to add a maxsize here to ensure some limitations are
        # being set (currently our limits are enforced by collector_threads but that would become obsolete once we
        # start enqueuing events directly).
        self._queue = Queue()

    @staticmethod
    def get_thread_name():
        return SendTelemetryEventsHandler._THREAD_NAME

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

        # Queue.put() can block if the queue is full which can be an uninterruptible wait. Blocking for a max of
        # SendTelemetryEventsHandler._MAX_TIMEOUT seconds and raising a ServiceStoppedError to retry later.

        # Todo: Queue.put() will only raise a Full exception if a maxsize is set for the Queue. Once some size
        # limitations are set for the Queue, ensure to handle that correctly here.
        try:
            self._queue.put(event, timeout=SendTelemetryEventsHandler._MAX_TIMEOUT)
        except Exception as error:
            raise ServiceStoppedError(
                "Unable to enqueue due to: {0}, stopping any more enqueuing until the next run".format(ustr(error)))

    def _wait_for_event_in_queue(self):
        """
        Wait for atleast one event in Queue or timeout after SendTelemetryEventsHandler._MAX_TIMEOUT seconds.
        In case of a timeout, set the event to None.
        :return: event if an event is added to the Queue or None to signify no events were added in queue.
        This would raise in case of an error.
        """
        try:
            event = self._queue.get(timeout=SendTelemetryEventsHandler._MAX_TIMEOUT)
            self._queue.task_done()
        except Empty:
            # No elements in Queue, return None
            event = None

        return event

    def _process_telemetry_thread(self):
        logger.info("Successfully started the {0} thread".format(self.get_thread_name()))
        try:
            # On demand wait, start processing as soon as there is any data available in the queue. In worst case,
            # also keep checking every SendTelemetryEventsHandler._MAX_TIMEOUT secs to avoid uninterruptible waits.
            # Incase the service is stopped but we have events in queue, ensure we send them out before killing the thread.
            while not self.stopped() or not self._queue.empty():
                first_event = self._wait_for_event_in_queue()
                if first_event:
                    # Start processing queue only if first event is not None (i.e. Queue has atleast 1 event),
                    # else do nothing
                    self._send_events_in_queue(first_event)

        except Exception as error:
            err_msg = "An unknown error occurred in the {0} thread main loop, stopping thread. Error: {1}, Stack: {2}".format(
                self.get_thread_name(), ustr(error), traceback.format_exc())
            add_event(op=WALAEventOperation.UnhandledError, message=err_msg, is_success=False)

    def _send_events_in_queue(self, first_event):
        # Process everything in Queue
        start_time = datetime.datetime.utcnow()
        while not self.stopped() and (self._queue.qsize() + 1) < self._MIN_EVENTS_TO_BATCH and (
                start_time + self._MIN_BATCH_WAIT_TIME) > datetime.datetime.utcnow():
            # To promote batching, we either wait for atleast _MIN_EVENTS_TO_BATCH events or _MIN_BATCH_WAIT_TIME secs
            # before sending out the first request to wireserver.
            # If the thread is requested to stop midway, we skip batching and send whatever we have in the queue.
            logger.verbose("Waiting for events to batch. Total events so far: {0}, Time elapsed: {1} secs",
                           self._queue.qsize()+1, (datetime.datetime.utcnow() - start_time).seconds)
            time.sleep(1)
        # Delete files after sending the data rather than deleting and sending
        self._protocol.report_event(self._get_events_in_queue(first_event))

    def _get_events_in_queue(self, first_event):
        yield first_event
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                self._queue.task_done()
                yield event
            except Exception as error:
                logger.error("Some exception when fetching event from queue: {0}, {1}".format(ustr(error),
                                                                                              traceback.format_exc()))