#!/usr/bin/env python

import os

def get_seq():
    latest_seq = -1;
    config_dir = os.path.join(os.getcwd(), "config")
    if os.path.isdir(config_dir):
        for item in os.listdir(config_dir):
            item_path = os.path.join(config_dir, item)
            if os.path.isfile(item_path):
                seperator = item.rfind(".")
                if seperator > 0 and item[seperator + 1:] == "settings":
                    seq = int(item[0: seperator])
                    if seq > latest_seq:
                        latest_seq = seq
    return latest_seq


succeed_status = """
[{
    "status": {
        "status": "success"
    }
}]
"""

if __name__ == "__main__":
    seq = get_seq()
    if seq >= 0:
        status_file = os.path.join(os.getcwd(), "status", "{0}.status".format(seq))
        with open(status_file, "w+") as status:
            status.write(succeed_status)
