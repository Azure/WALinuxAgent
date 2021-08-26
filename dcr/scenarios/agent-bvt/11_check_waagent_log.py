# The first import honors the folder structure of this project. The second import honors the folder structure
# when this test is being executed on remote machine. DCR is set up to first copy over files to the remote machine
# before executing them, where the scenario utils functions will be side-to-side with the test modules like this one.

from dungeon_crawler.scenarios_utils.check_waagent_log import check_waagent_log_for_errors


if __name__ == "__main__":
    check_waagent_log_for_errors()
