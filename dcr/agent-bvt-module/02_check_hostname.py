import os

from dungeon_crawler.constants import *
from dungeon_crawler.scenarios.interfaces import ITestClass


class TestClass(ITestClass):

    def __init__(self, metadata):
        super(TestClass, self).__init__(metadata)

    def run(self):
        """
        Test checking hostname which should be same as VM NAME
        """

        ret = False
        self.logger.debug("Checking hostname [04_check_hostname]")
        helpers_path = os.path.join(self.metadata[SCENARIO_PATH], 'helpers')
        resource_group_manager = self.metadata[RESOURCE_GROUP_MANAGER]
        vm_name = self.metadata[VM_NAME]

        remote_exec_results = resource_group_manager.remote_execute_with_output(
            vm_name=vm_name,
            parent_dir_path=helpers_path,
            file_name='check_hostname_remote.py')

        for result in remote_exec_results:
            exit_code, std_out, std_err, public_ip = result

            ret = False
            if exit_code != 0:
                self.logger.warning("Running check_hostname_remote.py remotely "
                                    "on %s failed, exit code: %s, std_err: %s",
                                    public_ip,
                                    exit_code,
                                    std_err)
            elif std_out is None or len(std_out) < 1:
                self.logger.warning("No std out is available.")
            else:
                host_name = std_out[0].strip()
                if host_name != vm_name:
                    self.logger.warning("Output of 'hostname' [%s] does not "
                                        "match VM name [%s].",
                                        host_name,
                                        vm_name)
                else:
                    self.logger.debug("Hostname reported as %s", host_name)
                    ret = True

        return ret
