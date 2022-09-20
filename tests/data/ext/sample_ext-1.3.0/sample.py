#!./python.sh
import json
import os
import re
import sys


def get_seq(requested_ext_name=None):
    if 'ConfigSequenceNumber' in os.environ:
        # Always use the environment variable if available
        return int(os.environ['ConfigSequenceNumber'])

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


def get_extension_state_prefix():
    requested_ext_name = None if 'ConfigExtensionName' not in os.environ else os.environ['ConfigExtensionName']
    seq = get_seq(requested_ext_name)
    if seq >= 0:
        if requested_ext_name is not None:
            seq = "{0}.{1}".format(requested_ext_name, seq)
        return seq

    return None


def read_settings_file(seq_prefix):
    settings_file = os.path.join(os.getcwd(), "config", "{0}.settings".format(seq_prefix))
    if not os.path.exists(settings_file):
        print("No settings found for {0}".format(settings_file))
        return None

    with open(settings_file, "rb") as file_:
        return json.loads(file_.read().decode("utf-8"))


def report_status(seq_prefix, status="success", message=None):
    status_path = os.path.join(os.getcwd(), "status")
    if not os.path.exists(status_path):
        os.makedirs(status_path)
    status_file = os.path.join(status_path, "{0}.status".format(seq_prefix))
    with open(status_file, "w+") as status_:
        status_to_report = {
            "status": {
                "status": status
            }
        }
        if message is not None:
            status_to_report['status']["formattedMessage"] = {
                "lang": "en-US",
                "message": message
            }
        status_.write(json.dumps([status_to_report]))


if __name__ == "__main__":
    prefix = get_extension_state_prefix()
    if prefix is None:
        print("No sequence number found!")
        sys.exit(-1)

    try:
        settings = read_settings_file(prefix)
    except Exception as error:
        msg = "Error when trying to fetch settings {0}.settings: {1}".format(prefix, error)
        print(msg)
        report_status(prefix, status="error", message=msg)
    else:
        status_msg = None
        if settings is not None:
            print(settings)
            try:
                status_msg = settings['runtimeSettings'][0]['handlerSettings']['publicSettings']['message']
            except Exception:
                # Settings might not contain the message. Ignore error if not found
                pass

        report_status(prefix, message=status_msg)
