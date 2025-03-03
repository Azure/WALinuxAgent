#!/usr/bin/env pypy3

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
# Adds extension events for each provided extension and verifies the TelemetryEventsCollector collected or dropped them
#

import argparse
import json
import os
import sys
import time
import uuid

from assertpy import fail
from datetime import datetime, timedelta
from random import choice
from typing import List

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log


def add_extension_events(extensions: List[str], bad_event_count=0, no_of_events_per_extension=50):
    def missing_key(bad_event):
        key = choice(list(bad_event.keys()))
        del bad_event[key]
        return "MissingKeyError: {0}".format(key)

    def oversize_error(bad_event):
        bad_event["EventLevel"] = "ThisIsAnOversizeError\n" * 300
        return "OversizeEventError"

    def empty_message(bad_event):
        bad_event["Message"] = ""
        return "EmptyMessageError"

    errors = [
        missing_key,
        oversize_error,
        empty_message
    ]

    sample_ext_event = {
        "EventLevel": "INFO",
        "Message": "Starting IaaS ScriptHandler Extension v1",
        "Version": "1.0",
        "TaskName": "Extension Info",
        "EventPid": "3228",
        "EventTid": "1",
        "OperationId": "519e4beb-018a-4bd9-8d8e-c5226cf7f56e",
        "TimeStamp": "2019-12-12T01:20:05.0950244Z"
    }

    sample_messages = [
        "Starting IaaS ScriptHandler Extension v1",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        "The quick brown fox jumps over the lazy dog",
        "Cursus risus at ultrices mi.",
        "Doing Something",
        "Iaculis eu non diam phasellus.",
        "Doing other thing",
        "Look ma, lemons",
        "Pretium quam vulputate dignissim suspendisse.",
        "Man this is insane",
        "I wish it worked as it should and not as it ain't",
        "Ut faucibus pulvinar elementum integer enim neque volutpat ac tincidunt."
        "Did you get any of that?",
        "Non-English message -  此文字不是英文的"
        "κόσμε",
        "�",
        "Quizdeltagerne spiste jordbær med fløde, mens cirkusklovnen Wolther spillede på xylofon.",
        "Falsches Üben von Xylophonmusik quält jeden größeren Zwerg",
        "Zwölf Boxkämpfer jagten Eva quer über den Sylter Deich",
        "Heizölrückstoßabdämpfung",
        "Γαζέες καὶ μυρτιὲς δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο",
        "Ξεσκεπάζω τὴν ψυχοφθόρα βδελυγμία",
        "El pingüino Wenceslao hizo kilómetros bajo exhaustiva lluvia y frío, añoraba a su querido cachorro.",
        "Portez ce vieux whisky au juge blond qui fume sur son île intérieure, à côté de l'alcôve ovoïde, où les bûches",
        "se consument dans l'âtre, ce qui lui permet de penser à la cænogenèse de l'être dont il est question",
        "dans la cause ambiguë entendue à Moÿ, dans un capharnaüm qui, pense-t-il, diminue çà et là la qualité de son œuvre.",
        "D'fhuascail Íosa, Úrmhac na hÓighe Beannaithe, pór Éava agus Ádhaimh",
        "Árvíztűrő tükörfúrógép",
        "Kæmi ný öxi hér ykist þjófum nú bæði víl og ádrepa",
        "Sævör grét áðan því úlpan var ónýt",
        "いろはにほへとちりぬるを わかよたれそつねならむ うゐのおくやまけふこえて あさきゆめみしゑひもせす",
        "イロハニホヘト チリヌルヲ ワカヨタレソ ツネナラム ウヰノオクヤマ ケフコエテ アサキユメミシ ヱヒモセスン",
        "? דג סקרן שט בים מאוכזב ולפתע מצא לו חברה איך הקליטה"
        "Pchnąć w tę łódź jeża lub ośm skrzyń fig",
        "В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!",
        "๏ เป็นมนุษย์สุดประเสริฐเลิศคุณค่า  กว่าบรรดาฝูงสัตว์เดรัจฉาน",
        "Pijamalı hasta, yağız şoföre çabucak güvendi."
    ]

    for ext in extensions:
        bad_count = bad_event_count
        event_dir = os.path.join("/var/log/azure/", ext, "events")
        if not os.path.isdir(event_dir):
            fail(f"Expected events dir: {event_dir} does not exist")

        log.info("")
        log.info("Expected dir: {0} exists".format(event_dir))
        log.info("Creating random extension events for {0}. No of Good Events: {1}, No of Bad Events: {2}".format(
            ext, no_of_events_per_extension - bad_event_count, bad_event_count))

        new_opr_id = str(uuid.uuid4())
        event_list = []

        for _ in range(no_of_events_per_extension):
            event = sample_ext_event.copy()
            event["OperationId"] = new_opr_id
            event["TimeStamp"] = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
            event["Message"] = choice(sample_messages)

            if bad_count != 0:
                # Make this event a bad event
                reason = choice(errors)(event)
                bad_count -= 1

                # Missing key error might delete the TaskName key from the event
                if "TaskName" in event:
                    event["TaskName"] = "{0}. This is a bad event: {1}".format(event["TaskName"], reason)
                else:
                    event["EventLevel"] = "{0}. This is a bad event: {1}".format(event["EventLevel"], reason)

            event_list.append(event)

        file_name = os.path.join(event_dir, '{0}.json'.format(int(time.time() * 1000000)))
        log.info("Create json with extension events in event directory: {0}".format(file_name))
        with open("{0}.tmp".format(file_name), 'w+') as f:
            json.dump(event_list, f)
        os.rename("{0}.tmp".format(file_name), file_name)


def wait_for_extension_events_dir_empty(extensions: List[str]):
    # By ensuring events dir to be empty, we verify that the telemetry events collector has completed its run
    start_time = datetime.now()
    timeout = timedelta(minutes=2)
    ext_event_dirs = [os.path.join("/var/log/azure/", ext, "events") for ext in extensions]

    while (start_time + timeout) >= datetime.now():
        log.info("")
        log.info("Waiting for extension event directories to be empty...")
        all_dir_empty = True
        for event_dir in ext_event_dirs:
            if not os.path.exists(event_dir) or len(os.listdir(event_dir)) != 0:
                log.info("Dir: {0} is not yet empty".format(event_dir))
                all_dir_empty = False

        if all_dir_empty:
            log.info("Extension event directories are empty: \n{0}".format(ext_event_dirs))
            return

        time.sleep(20)

    fail("Extension events dir not empty before 2 minute timeout")


def main():
    # This test is a best effort test to ensure that the agent does not throw any errors while trying to transmit
    # events to wireserver. We're not validating if the events actually make it to wireserver.

    parser = argparse.ArgumentParser()
    parser.add_argument("--extensions", dest='extensions', type=str, required=True)
    parser.add_argument("--num_events_total", dest='num_events_total', type=int, required=True)
    parser.add_argument("--num_events_bad", dest='num_events_bad', type=int, required=False, default=0)
    args, _ = parser.parse_known_args()

    extensions = args.extensions.split(',')
    add_extension_events(extensions=extensions, bad_event_count=args.num_events_bad,
                         no_of_events_per_extension=args.num_events_total)

    # Ensure that the event collector ran after adding the events
    wait_for_extension_events_dir_empty(extensions=extensions)

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)
    found_error = False
    agent_log = AgentLog()

    log.info("")
    log.info("Check that the TelemetryEventsCollector did not emit any errors while collecting and reporting events...")
    telemetry_event_collector_name = "TelemetryEventsCollector"
    for agent_record in agent_log.read():
        if agent_record.thread == telemetry_event_collector_name and agent_record.level == "ERROR":
            found_error = True
            log.info("waagent.log contains the following errors emitted by the {0} thread: \n{1}".format(telemetry_event_collector_name, agent_record))

    if found_error:
        fail("Found error(s) emitted by the TelemetryEventsCollector, but none were expected.")
    log.info("The TelemetryEventsCollector did not emit any errors while collecting and reporting events")

    for ext in extensions:
        good_count = args.num_events_total - args.num_events_bad
        log.info("")
        if not agent_log.agent_log_contains("Collected {0} events for extension: {1}".format(good_count, ext)):
            fail("The TelemetryEventsCollector did not collect the expected number of events: {0} for {1}".format(good_count, ext))
        log.info("All {0} good events for {1} were collected by the TelemetryEventsCollector".format(good_count, ext))

        if args.num_events_bad != 0:
            log.info("")
            if not agent_log.agent_log_contains("Dropped events for Extension: {0}".format(ext)):
                fail("The TelemetryEventsCollector did not drop bad events for {0} as expected".format(ext))
            log.info("The TelemetryEventsCollector dropped bad events for {0} as expected".format(ext))

    sys.exit(0)


if __name__ == "__main__":
    main()
