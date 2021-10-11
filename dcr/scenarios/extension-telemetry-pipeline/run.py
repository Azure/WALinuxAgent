import glob
import os
import random
import time

from dotenv import load_dotenv

from dcr.scenario_utils.check_waagent_log import is_data_in_waagent_log, check_waagent_log_for_errors
from dcr.scenario_utils.models import get_vm_data_from_env
from dcr.scenario_utils.test_orchestrator import TestFuncObj
from dcr.scenario_utils.test_orchestrator import TestOrchestrator
from etp_helpers import add_extension_events_and_get_count, wait_for_extension_events_dir_empty


def add_good_extension_events_and_verify():
    max_events = random.randint(10, 50)
    print("Creating a total of {0} events".format(max_events))
    ext_event_count = add_extension_events_and_get_count(no_of_events_per_extension=max_events)

    # Ensure that the event collector ran after adding the events
    wait_for_extension_events_dir_empty()

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)
    check_waagent_log_for_errors()

    for ext_name in ext_event_count:
        good_count = ext_event_count[ext_name]['good']
        is_data_in_waagent_log("Collected {0} events for extension: {1}".format(good_count, ext_name))


def add_bad_events_and_verify_count():
    max_events = random.randint(15, 50)
    print("Creating a total of {0} events".format(max_events))
    extension_event_count = add_extension_events_and_get_count(bad_event_count=random.randint(5, max_events - 5),
                                                               no_of_events_per_extension=max_events)

    # Ensure that the event collector ran after adding the events
    wait_for_extension_events_dir_empty()

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)

    for ext_name in extension_event_count:
        good_count = extension_event_count[ext_name]['good']
        is_data_in_waagent_log("Dropped events for Extension: {0}".format(ext_name))
        is_data_in_waagent_log("Collected {0} events for extension: {1}".format(good_count, ext_name))


def verify_etp_enabled():
    # Assert from log if ETP is enabled
    is_data_in_waagent_log('Extension Telemetry pipeline enabled: True')

    # Since ETP is enabled, events dir should have been created for all extensions
    event_dirs = glob.glob(os.path.join("/var/log/azure/", "*", "events"))
    assert event_dirs, "No extension event directories exist!"

    verified = True
    for event_dir in event_dirs:
        exists = os.path.exists(event_dir)
        print("Dir: {0} exists: {1}".format(event_dir, exists))
        verified = verified and exists

    if not verified:
        raise AssertionError("Event directory not found for all extensions!")


if __name__ == '__main__':
    tests = [
        TestFuncObj("Verify ETP enabled", verify_etp_enabled, raise_on_error=True, retry=3),
        TestFuncObj("Add Good extension events and verify", add_good_extension_events_and_verify),
        TestFuncObj("Add Bad extension events and verify", add_bad_events_and_verify_count),
        TestFuncObj("Verify all events processed", wait_for_extension_events_dir_empty),
    ]

    test_orchestrator = TestOrchestrator("ETPTests-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-etp-vm.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
