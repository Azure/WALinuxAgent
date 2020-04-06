# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

import os
import shutil
import tarfile
import tempfile

from azurelinuxagent.common.utils.fileutil import rm_dirs, mkdir, rm_files, write_file
from azurelinuxagent.common.logcollector import LogCollector
from tests.tools import AgentTestCase, patch


SMALL_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
LARGE_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


class TestLogCollector(AgentTestCase):

    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        prefix = "{0}_".format(cls.__class__.__name__)
        cls.tmp_dir = tempfile.mkdtemp(prefix=prefix)

        cls._mock_constants()

    @classmethod
    def _mock_constants(cls):
        cls.manifest_path = os.path.join(cls.tmp_dir, "logcollector_manifest")

        cls.log_collector_dir = os.path.join(cls.tmp_dir, "logcollector")
        cls.mock_log_collector_dir = patch("azurelinuxagent.common.logcollector.LOG_COLLECTOR_DIR",
                                           cls.log_collector_dir)

        cls.truncated_files_dir = os.path.join(cls.tmp_dir, "truncated")
        cls.mock_truncated_files_dir = patch("azurelinuxagent.common.logcollector.TRUNCATED_FILES_DIR",
                                             cls.truncated_files_dir)

        cls.output_archive_path = os.path.join(cls.log_collector_dir, "logs.tar")
        cls.mock_output_archive_path = patch("azurelinuxagent.common.logcollector.OUTPUT_ARCHIVE_PATH",
                                             cls.output_archive_path)

        cls.output_results_file_path = os.path.join(cls.log_collector_dir, "results.txt")
        cls.mock_output_results_file_path = patch("azurelinuxagent.common.logcollector.OUTPUT_RESULTS_FILE_PATH",
                                                  cls.output_results_file_path)

        cls.mock_log_collector_dir.start()
        cls.mock_truncated_files_dir.start()
        cls.mock_output_archive_path.start()
        cls.mock_output_results_file_path.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_log_collector_dir.stop()
        cls.mock_truncated_files_dir.stop()
        cls.mock_output_archive_path.stop()
        cls.mock_output_results_file_path.stop()

        shutil.rmtree(cls.tmp_dir)

        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)
        self._build_test_data()
        self._build_manifest(self.manifest_path)

    def tearDown(self):
        rm_dirs(self.root_collect_dir)
        rm_files(self.output_archive_path)
        AgentTestCase.tearDown(self)

    @classmethod
    def _build_test_data(cls):
        """
        Build a dummy file structure which will be used as a foundation for the log collector tests
        """
        cls.root_collect_dir = os.path.join(cls.tmp_dir, "files_to_collect")
        mkdir(cls.root_collect_dir)

        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "waagent.log"),
                                          SMALL_FILE_SIZE)  # small text file
        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "waagent.log.1"),
                                          LARGE_FILE_SIZE)  # large text file
        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "waagent.log.2.gz"),
                                          SMALL_FILE_SIZE, binary=True)  # small binary file
        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "waagent.log.3.gz"),
                                          LARGE_FILE_SIZE, binary=True)  # large binary file

        mkdir(os.path.join(cls.root_collect_dir, "another_dir"))
        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "less_important_file"),
                                          SMALL_FILE_SIZE)
        cls._create_file_of_specific_size(os.path.join(cls.root_collect_dir, "another_dir", "least_important_file"),
                                          SMALL_FILE_SIZE)

    @classmethod
    def _build_manifest(cls, manifest_file):
        """
        Files listed in the manifest will be collected, others will be ignored
        """
        files = [
            os.path.join(cls.root_collect_dir, "waagent*"),
            os.path.join(cls.root_collect_dir, "less_important_file*"),
            os.path.join(cls.root_collect_dir, "another_dir", "least_important_file"),
            os.path.join(cls.root_collect_dir, "non_existing_file"),
        ]

        with open(manifest_file, "w") as fh:
            for file in files:
                fh.write("copy,{0}\n".format(file))

    @staticmethod
    def _create_file_of_specific_size(file_path, file_size, binary=False):
        binary_descriptor = "b" if binary else ""
        data = b'0' if binary else '0'

        with open(file_path, "w{0}".format(binary_descriptor)) as fh:
            fh.seek(file_size - 1)
            fh.write(data)

    @staticmethod
    def _truncated_path(normal_path):
        return "truncated_" + normal_path.replace(os.path.sep, "_")

    def _assert_files_are_in_archive(self, expected_files):
        with tarfile.open(self.output_archive_path, "r") as archive:
            archive_files = archive.getnames()

            for file in expected_files:
                if file.lstrip(os.path.sep) not in archive_files:
                    self.fail("File {0} was supposed to be collected, but is not present in the archive!".format(file))

        self.assertTrue(True)

    def _assert_files_are_not_in_archive(self, unexpected_files):
        with tarfile.open(self.output_archive_path, "r") as archive:
            archive_files = archive.getnames()

            for file in unexpected_files:
                if file.lstrip(os.path.sep) in archive_files:
                    self.fail("File {0} wasn't supposed to be collected, but is present in the archive!".format(file))

        self.assertTrue(True)

    def _get_uncompressed_file_size(self, file):
        with tarfile.open(self.output_archive_path, "r") as archive:
            return archive.getinfo(file.lstrip(os.path.sep)).size

    def _get_number_of_files_in_archive(self):
        with tarfile.open(self.output_archive_path, "r") as archive:
            return len(archive.getnames())

    def test_log_collector_parses_commands_in_manifest(self):
        # Ensure familiar commands are parsed and unknowns are ignored (like diskinfo)
        file_to_collect = os.path.join(self.root_collect_dir, "waagent.log")
        folder_to_list = self.root_collect_dir

        manifest_content = """
echo,### Test header ###
ll,{0}
copy,{1}
diskinfo,""".format(folder_to_list, file_to_collect)

        manifest_file_path = os.path.join(self.tmp_dir, "manifest")
        write_file(manifest_file_path, manifest_content)

        lc = LogCollector(manifest_file_path)
        archive = lc.collect_logs()

        with open(self.output_results_file_path, "r") as fh:
            results = fh.readlines()

        # Assert echo was parsed
        self.assertEquals("### Test header ###\n", results[0])
        # Assert ll was parsed
        self.assertTrue("ll {0}".format(folder_to_list) in results[1])
        # Assert copy was parsed
        self.assertIsNotNone(archive)
        self._assert_files_are_in_archive(expected_files=[file_to_collect])

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(1, no_files, "Expected 1 file in archive, found {0}!".format(no_files))

    def test_log_collector_should_collect_all_files(self):
        # All files in the manifest should be collected, since none of them are over the individual file size limit,
        # and combined they do not cross the archive size threshold.
        lc = LogCollector(self.manifest_path)
        archive = lc.collect_logs()

        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "waagent.log.3.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        self._assert_files_are_in_archive(expected_files)
        self.assertIsNotNone(archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(6, no_files, "Expected 6 files in archive, found {0}!".format(no_files))

    def test_log_collector_should_truncate_large_text_files_and_ignore_large_binary_files(self):
        # Set the size limit so that some files are too large to collect in full.
        with patch("azurelinuxagent.common.logcollector.FILE_SIZE_LIMIT", SMALL_FILE_SIZE):
            lc = LogCollector(self.manifest_path)
            archive = lc.collect_logs()

        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            self._truncated_path(os.path.join(self.root_collect_dir, "waagent.log.1")),  # this file should be truncated
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "waagent.log.3.gz")  # binary files cannot be truncated, ignore it
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        self.assertIsNotNone(archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(5, no_files, "Expected 5 files in archive, found {0}!".format(no_files))

    def test_log_collector_should_prioritize_important_files_if_archive_too_big(self):
        # Set the archive size limit so that not all files can be collected. In that case, files will be added to the
        # archive according to their priority.

        # Specify files that have priority. The list is ordered, where the first entry has the highest priority.
        must_collect_files = [
            os.path.join(self.root_collect_dir, "waagent*"),
            os.path.join(self.root_collect_dir, "less_important_file*")
        ]

        with patch("azurelinuxagent.common.logcollector.ARCHIVE_SIZE_LIMIT", 10 * 1024 * 1024):
            with patch("azurelinuxagent.common.logcollector.MUST_COLLECT_FILES_REGEX", must_collect_files):
                lc = LogCollector(self.manifest_path)
                archive = lc.collect_logs()

        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "waagent.log.3.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        self.assertIsNotNone(archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(3, no_files, "Expected 3 files in archive, found {0}!".format(no_files))

        # Second collection, if a file got deleted, delete it from the archive and add next file on the priority list
        # if there is enough space.
        rm_files(os.path.join(self.root_collect_dir, "waagent.log.3.gz"))

        with patch("azurelinuxagent.common.logcollector.ARCHIVE_SIZE_LIMIT", 10 * 1024 * 1024):
            with patch("azurelinuxagent.common.logcollector.MUST_COLLECT_FILES_REGEX", must_collect_files):
                second_archive = lc.collect_logs()

        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "waagent.log.3.gz")
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        self.assertIsNotNone(second_archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(5, no_files, "Expected 5 files in archive, found {0}!".format(no_files))

    def test_log_collector_should_update_archive_when_files_are_new_or_modified_or_deleted(self):
        # Ensure the archive reflects the state of files on the disk at collection time. If a file was updated, it
        # needs to be updated in the archive, deleted if removed from disk, and added if not previously seen.
        lc = LogCollector(self.manifest_path)
        first_archive = lc.collect_logs()

        # Everything should be in the archive
        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "waagent.log.3.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        self._assert_files_are_in_archive(expected_files)
        self.assertIsNotNone(first_archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(6, no_files, "Expected 6 files in archive, found {0}!".format(no_files))

        # Update a file, create a new one (that is covered by the manifest and will be collected) and delete one
        self._create_file_of_specific_size(os.path.join(self.root_collect_dir, "waagent.log"),
                                           LARGE_FILE_SIZE)  # update existing file
        self._create_file_of_specific_size(os.path.join(self.root_collect_dir, "less_important_file.1"),
                                           LARGE_FILE_SIZE)
        rm_files(os.path.join(self.root_collect_dir, "waagent.log.1"))

        second_archive = lc.collect_logs()
        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "waagent.log.3.gz"),
            os.path.join(self.root_collect_dir, "less_important_file"),
            os.path.join(self.root_collect_dir, "less_important_file.1"),
            os.path.join(self.root_collect_dir, "another_dir", "least_important_file")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "waagent.log.1")
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        file = os.path.join(self.root_collect_dir, "waagent.log")
        new_file_size = self._get_uncompressed_file_size(file)
        self.assertEquals(LARGE_FILE_SIZE, new_file_size, "File {0} hasn't been updated! New size is {0}, but "
                                                          "should be {1}.".format(file, new_file_size, LARGE_FILE_SIZE))

        self.assertIsNotNone(second_archive)

        no_files = self._get_number_of_files_in_archive()
        self.assertEquals(6, no_files, "Expected 6 files in archive, found {0}!".format(no_files))
