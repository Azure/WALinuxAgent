import argparse
import sys


from dungeon_crawler.scenarios_utils.check_waagent_log import is_data_in_waagent_log
from dungeon_crawler.scenarios_utils.common_tools import ustr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", dest='data', required=True)
    args, _ = parser.parse_known_args()

    print("Verifying data: {0} in waagent.log".format(args.data))
    found = False

    try:
        found = is_data_in_waagent_log(args.data)
        print("Found data: {0} in agent log".format(args.data))
    except Exception as e:
        print("Error thrown when searching for test data in agent log: {0}".format(ustr(e)))

    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()