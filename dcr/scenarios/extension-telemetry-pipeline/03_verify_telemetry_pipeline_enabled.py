import glob
import os
import sys

from dungeon_crawler.scenarios_utils.check_waagent_log import is_data_in_waagent_log


def verify_from_log():
    verified = is_data_in_waagent_log('Extension Telemetry pipeline enabled: True')

    if not verified:
        sys.exit(1)


def verify_events_dir_exists():
    # Since ETP is enabled, events dir should have been created for all extensions
    event_dirs = glob.glob(os.path.join("/var/log/azure/", "*", "events"))
    assert event_dirs, "No extension event directories exist!"

    verified = True
    for event_dir in event_dirs:
        exists = os.path.exists(event_dir)
        print("Dir: {0} exists: {1}".format(event_dir, exists))
        verified = verified and exists

    if not verified:
        print("Event directory not found for all extensions!")
        sys.exit(1)


if __name__ == "__main__":
    verify_from_log()
    verify_events_dir_exists()

