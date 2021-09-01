import random
import sys
import time

from dungeon_crawler.scenarios_utils.check_waagent_log import is_data_in_waagent_log
from dungeon_crawler.scenarios_utils.etp_helpers import add_extension_events_and_get_count, wait_for_extension_events_dir_empty

def add_events_and_verify_count():
    max_events = random.randint(15, 50)
    print("Creating a total of {0} events".format(max_events))
    extension_event_count = add_extension_events_and_get_count(bad_event_count=random.randint(5, max_events-5),
                                                               no_of_events_per_extension=max_events)

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)
    exit_code = 0

    for ext_name in extension_event_count:
        good_count = extension_event_count[ext_name]['good']
        if not (is_data_in_waagent_log("Dropped events for Extension: {0}".format(ext_name)) and is_data_in_waagent_log(
                "Collected {0} events for extension: {1}".format(good_count, ext_name))):
            exit_code += 1

    sys.exit(exit_code)


if __name__ == "__main__":
    # This test is a best effort test to ensure that the agent does not throw any errors while trying to transmit
    # events to wireserver. We're not validating if the events actually make it to wireserver.

    try:
        wait_for_extension_events_dir_empty()
    except AssertionError as error:
        print(error)
        sys.exit(1)

    add_events_and_verify_count()