import glob
import os
import shutil
import sys

from junitparser import JUnitXml

from dcr.scenario_utils.logging_utils import get_logger

logger = get_logger("dcr.scripts.orchestrator.generate_test_files")


def merge_xml_files(test_file_pattern):
    xml_data = JUnitXml()
    staging_dir = os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY']

    for test_file in glob.glob(test_file_pattern):
        xml_data += JUnitXml.fromfile(test_file)
        # Move file to harvest dir to save state and not publish the same test twice
        shutil.move(test_file, os.path.join(staging_dir, "harvest", os.path.basename(test_file)))

    if xml_data.tests > 0:
        # Merge all files into a single file for cleaner output
        output_file_name = f"test-results-{os.environ['SCENARIONAME']}-{os.environ['DISTRONAME']}.xml"
        xml_data.write(os.path.join(staging_dir, output_file_name))
    else:
        logger.info(f"No test files found for pattern: {test_file_pattern}")


if __name__ == "__main__":
    try:
        merge_xml_files(test_file_pattern=sys.argv[1])
    except Exception as err:
        logger.exception(
            f"Ran into error when trying to merge test cases. Ignoring the rest: {err}")

