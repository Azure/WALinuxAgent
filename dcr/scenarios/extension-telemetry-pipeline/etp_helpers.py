# -*- coding: utf-8 -*-
from __future__ import print_function

import glob
import json
import os
import time
import uuid
from datetime import datetime, timedelta
from random import choice


def wait_for_extension_events_dir_empty(timeout=timedelta(minutes=2)):
    # By ensuring events dir to be empty, we verify that the telemetry events collector has completed its run
    event_dirs = glob.glob(os.path.join("/var/log/azure/", "*", "events"))
    start_time = datetime.now()

    assert event_dirs, "No extension event directories exist!"

    while (start_time + timeout) >= datetime.now():
        all_dir_empty = True
        for event_dir in event_dirs:
            if not os.path.exists(event_dir) or len(os.listdir(event_dir)) != 0:
                print("Dir: {0} not empty".format(event_dir))
                all_dir_empty = False
                break

        if all_dir_empty:
            return

        time.sleep(5)

    raise AssertionError("Extension events dir not empty!")


def add_extension_events_and_get_count(bad_event_count=0, no_of_events_per_extension=50):
    print("Creating random extension events now. No of Good Events: {0}, No of Bad Events: {1}".format(
        no_of_events_per_extension - bad_event_count, bad_event_count))

    def missing_key(make_bad_event):
        key = choice(list(make_bad_event.keys()))
        del make_bad_event[key]
        return "MissingKeyError: {0}".format(key)

    def oversize_error(make_bad_event):
        make_bad_event["EventLevel"] = "ThisIsAnOversizeErrorOnSteroids\n" * 300
        return "OversizeEventError"

    def empty_message(make_bad_event):
        make_bad_event["Message"] = ""
        return "EmptyMessageError"

    def oversize_file_limit(make_bad_event):
        make_bad_event["EventLevel"] = "MakeThisFileGreatAgain\n" * 30000
        return "OversizeEventFileSize"

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
    ]

    # Currently the GA cant send special chars in telemetry as the unicode changes were reverted.
    # Once its enabled again, we would add these messages back to our tests.
    # Should be enabled when this task is completed - https://msazure.visualstudio.com/One/_workitems/edit/8733946
    non_english_messages = [
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

    last_err = -1
    error_map = {
        0: missing_key,
        1: oversize_error,
        2: empty_message
    }

    ext_log_dir = "/var/log/azure/"

    total_counts = {}

    for ext_dir in os.listdir(ext_log_dir):
        events_dir = os.path.join(ext_log_dir, ext_dir, "events")
        if not os.path.isdir(events_dir):
            continue

        new_opr_id = str(uuid.uuid4())
        event_list = []
        good_count = 0
        bad_count = 0

        for _ in range(no_of_events_per_extension):
            event = sample_ext_event.copy()
            event["OperationId"] = new_opr_id
            event["TimeStamp"] = datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S.%fZ')
            event["Message"] = choice(sample_messages)

            if bad_count < bad_event_count:
                # Make this event a bad event by cycling through the possible errors
                last_err += 1
                reason = error_map[last_err % len(error_map)](event)
                bad_count += 1

                # Missing key error might delete the TaskName key from the event
                if "TaskName" in event:
                    event["TaskName"] = "{0}. BTW a bad event: {1}".format(event["TaskName"], reason)
                else:
                    event["EventLevel"] = "{0}. BTW a bad event: {1}".format(event["EventLevel"], reason)
            else:
                good_count += 1
            event_list.append(event)

        file_name = os.path.join(events_dir, '{0}.json'.format(int(time.time() * 1000000)))
        with open("{0}.tmp".format(file_name), 'w+') as f:
            json.dump(event_list, f)

        os.rename("{0}.tmp".format(file_name), file_name)

        counts = {
            "good": good_count,
            "bad": bad_count
        }

        print("OperationId: {0}; Extension: {1}; Count: {2}".format(new_opr_id, ext_dir, counts))

        if ext_dir in total_counts:
            total_counts[ext_dir]['good'] += good_count
            total_counts[ext_dir]['bad'] += bad_count
        else:
            total_counts[ext_dir] = counts

    return total_counts
