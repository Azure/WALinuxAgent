import random
import sys
import time

from dungeon_crawler.scenarios_utils.check_waagent_log import check_waagent_log_for_errors, is_data_in_waagent_log
from dungeon_crawler.scenarios_utils.etp_helpers import add_extension_events_and_get_count, \
    wait_for_extension_events_dir_empty

if __name__ == "__main__":
    # This test is a best effort test to ensure that the agent does not throw any errors while trying to transmit
    # events to wireserver. We're not validating if the events actually make it to wireserver.

    max_events = random.randint(10, 50)
    print("Creating a total of {0} events".format(max_events))
    ext_event_count = add_extension_events_and_get_count(no_of_events_per_extension=max_events)

    try:
        # Ensure that the event collector ran after adding the events
        wait_for_extension_events_dir_empty()
    except AssertionError as error:
        print(error)
        sys.exit(1)

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)
    exit_code = 0
    if not check_waagent_log_for_errors(exit_on_completion=False):
        exit_code += 1


    for ext_name in ext_event_count:
        good_count = ext_event_count[ext_name]['good']
        if not is_data_in_waagent_log("Collected {0} events for extension: {1}".format(good_count, ext_name)):
            exit_code += 1

    sys.exit(exit_code)