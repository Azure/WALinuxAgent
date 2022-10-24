import glob
import os
import random
import time

from dcr.scenario_utils.agent_log_parser import parse_agent_log_file
from dcr.scenario_utils.check_waagent_log import is_data_in_waagent_log, check_waagent_log_for_errors
from dcr.scenario_utils.extensions.CustomScriptExtension import CustomScriptExtension
from dcr.scenario_utils.extensions.VMAccessExtension import VMAccessExtension
from dcr.scenario_utils.test_orchestrator import TestFuncObj
from dcr.scenario_utils.test_orchestrator import TestOrchestrator
from etp_helpers import add_extension_events_and_get_count, wait_for_extension_events_dir_empty, \
    get_collect_telemetry_thread_name


def add_good_extension_events_and_verify(extension_names):
    max_events = random.randint(10, 50)
    print("Creating a total of {0} events".format(max_events))
    ext_event_count = add_extension_events_and_get_count(no_of_events_per_extension=max_events,
                                                         extension_names=extension_names)

    # Ensure that the event collector ran after adding the events
    wait_for_extension_events_dir_empty()

    # Sleep for a min to ensure that the TelemetryService has enough time to send events and report errors if any
    time.sleep(60)
    telemetry_event_collector_name = get_collect_telemetry_thread_name()
    errors_reported = False
    for agent_log_line in parse_agent_log_file():
        if agent_log_line.thread == telemetry_event_collector_name and agent_log_line.is_error:
            if not errors_reported:
                print(
                    f"waagent.log contains the following errors emitted by the {telemetry_event_collector_name} thread (none expected):")
                errors_reported = True
            print(agent_log_line.text.rstrip())

    for ext_name in ext_event_count:
        good_count = ext_event_count[ext_name]['good']
        is_data_in_waagent_log("Collected {0} events for extension: {1}".format(good_count, ext_name))


def add_bad_events_and_verify_count(extension_names):
    max_events = random.randint(15, 50)
    print("Creating a total of {0} events".format(max_events))
    extension_event_count = add_extension_events_and_get_count(bad_event_count=random.randint(5, max_events - 5),
                                                               no_of_events_per_extension=max_events,
                                                               extension_names=extension_names)

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

    if not all(os.path.exists(event_dir) for event_dir in event_dirs):
        raise AssertionError("Event directory not found for all extensions!")


def check_agent_log():
    # Since we're injecting bad events in the add_bad_events_and_verify_count() function test,
    # we expect some warnings to be emitted by the agent.
    # We're already verifying if these warnings are being emitted properly in the specified test, so ignoring those here.
    ignore = [
        {
            'message': r"Dropped events for Extension: Microsoft\.(OSTCExtensions.VMAccessForLinux|Azure.Extensions.CustomScript); Details:",
            'if': lambda log_line: log_line.level == "WARNING" and log_line.thread == get_collect_telemetry_thread_name()
        }
    ]
    check_waagent_log_for_errors(ignore=ignore)


if __name__ == '__main__':

    extensions_to_verify = [CustomScriptExtension.META_DATA.handler_name, VMAccessExtension.META_DATA.handler_name]
    tests = [
        TestFuncObj("Verify ETP enabled", verify_etp_enabled, raise_on_error=True, retry=3),
        TestFuncObj("Add Good extension events and verify",
                    lambda: add_good_extension_events_and_verify(extensions_to_verify)),
        TestFuncObj("Add Bad extension events and verify",
                    lambda: add_bad_events_and_verify_count(extensions_to_verify)),
        TestFuncObj("Verify all events processed", wait_for_extension_events_dir_empty),
        TestFuncObj("Check Agent log", check_agent_log),
    ]

    test_orchestrator = TestOrchestrator("ETPTests-VM", tests=tests)
    test_orchestrator.run_tests()
    test_orchestrator.generate_report_on_vm("test-result-etp-vm.xml")
    assert not test_orchestrator.failed, f"Test Suite: {test_orchestrator.name} failed"
