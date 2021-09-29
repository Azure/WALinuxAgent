import os
import shutil

import traceback

import tempfile

from dungeon_crawler.constants import DIR_PATH
from dungeon_crawler.scenarios.interfaces import ITestClass, RESULTS_PATH, TEST_SUITE_NAME


class TestClass(ITestClass):

    def run(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            src_dir = os.path.join("/var", "log", "svgs")
            dest_dir = os.path.join(tmp_dir, format(self.metadata[TEST_SUITE_NAME]))
            results = self.resource_group_manager.get_file_from_vm(vm_name=self.vm_name, file_name="*",
                                                                   file_source_dir=src_dir, file_dest_dir=dest_dir)
            self.log("Trying to fetch svg file from VM results: ")
            for res in results:
                ec, stdout, stderr = res
                self.log("\tExit Code: {0}\n\tStdout: {1}\n\tStderr: {2}".format(ec, stdout, stderr))

            return self.verify_and_move_files(dest_dir)
        except Exception as e:
            self.log("\nRan into error: {0}; {1}".format(e, traceback.format_exc()))
            return False
        finally:
            # Finally delete the temp_dir
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def verify_and_move_files(self, dest_dir):

        if not os.path.exists(dest_dir):
            self.log("No SVG files found in: {0}".format(dest_dir))
            return False

        parent, _ = os.path.split(self.metadata[RESULTS_PATH])
        dungeon = os.path.join(parent, DIR_PATH)

        for svg_file in os.listdir(dest_dir):
            # Move files to the dungeon/ directory from the results/ dir
            dst = os.path.join(dungeon, "{0}-{1}".format(self.metadata[TEST_SUITE_NAME], svg_file))
            os.replace(src=os.path.join(dest_dir, svg_file), dst=dst)

        return True
