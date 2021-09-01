import sys

from dungeon_crawler.scenarios_utils.etp_helpers import wait_for_extension_events_dir_empty

if __name__ == "__main__":

    try:
        wait_for_extension_events_dir_empty()
    except AssertionError as error:
        print(error)
        sys.exit(1)