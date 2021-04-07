#!/usr/bin/env python

import os
import re


def get_seq(requested_ext_name=None):
    if 'ConfigSequenceNumber' in os.environ:
        # Always use the environment variable if available
        return os.environ['ConfigSequenceNumber']

    latest_seq = -1
    largest_modified_time = 0
    config_dir = os.path.join(os.getcwd(), "config")
    if os.path.isdir(config_dir):
        for item in os.listdir(config_dir):
            item_path = os.path.join(config_dir, item)
            if os.path.isfile(item_path):
                match = re.search("((?P<ext_name>\\w+)\\.)*(?P<seq_no>\\d+)\\.settings", item_path)
                if match is not None:
                    ext_name = match.group('ext_name')
                    if requested_ext_name is not None and ext_name != requested_ext_name:
                        continue
                    curr_seq_no = int(match.group("seq_no"))
                    curr_modified_time = os.path.getmtime(item_path)
                    if curr_modified_time > largest_modified_time:
                        latest_seq = curr_seq_no
                        largest_modified_time = curr_modified_time

    return latest_seq


succeed_status = """
[{
    "status": {
        "status": "success"
    }
}]
"""

if __name__ == "__main__":
    requested_ext_name = None if 'ConfigExtensionName' not in os.environ else os.environ['ConfigExtensionName']
    seq = get_seq(requested_ext_name)
    if seq >= 0:
        status_path = os.path.join(os.getcwd(), "status")
        if not os.path.exists(status_path):
            os.makedirs(status_path)
        if requested_ext_name is not None:
            seq = "{0}.{1}".format(requested_ext_name, seq)
        status_file = os.path.join(status_path, "{0}.status".format(seq))
        with open(status_file, "w+") as status:
            status.write(succeed_status)
