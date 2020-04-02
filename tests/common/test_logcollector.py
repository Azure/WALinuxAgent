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
import tempfile
import zipfile

from azurelinuxagent.common.utils.fileutil import rm_dirs, mkdir
from azurelinuxagent.common.logcollector import LogCollector
from tests.tools import AgentTestCase, patch, data_dir


class TestLogCollector(AgentTestCase):

    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()

        prefix = "{0}_".format(cls.__class__.__name__)
        cls.tmp_dir = tempfile.mkdtemp(prefix=prefix)
        cls._build_test_data()

        cls.normal_manifest_path = os.path.join(data_dir, "logcollector", "manifest-normal")
        cls.mock_normal_manifest_path = patch("azurelinuxagent.common.logcollector.NORMAL_COLLECTION_MANIFEST_PATH",
                                              cls.normal_manifest_path)

        cls.full_manifest_path = os.path.join(data_dir, "logcollector", "manifest-full")
        cls.mock_full_manifest_path = patch("azurelinuxagent.common.logcollector.FULL_COLLECTION_MANIFEST_PATH",
                                            cls.full_manifest_path)

        cls.log_collector_dir = os.path.join(cls.tmp_dir, "logcollector")
        cls.mock_log_collector_dir = patch("azurelinuxagent.common.logcollector.LOG_COLLECTOR_DIR",
                                           cls.log_collector_dir)

        cls.truncated_files_dir = os.path.join(cls.tmp_dir, "truncated")
        cls.mock_truncated_files_dir = patch("azurelinuxagent.common.logcollector.TRUNCATED_FILES_DIR",
                                             cls.truncated_files_dir)

        cls.output_archive_path = os.path.join(cls.log_collector_dir, "logs.zip")
        cls.mock_output_archive_path = patch("azurelinuxagent.common.logcollector.OUTPUT_ARCHIVE_PATH",
                                             cls.output_archive_path)

        cls.output_results_file_path = os.path.join(cls.log_collector_dir, "results.txt")
        cls.mock_output_results_file_path = patch("azurelinuxagent.common.logcollector.OUTPUT_RESULTS_FILE_PATH",
                                                  cls.output_results_file_path)

        cls.must_collect_files = [
            os.path.join(cls.root_collect_dir, "waagent*")
        ]
        cls.mock_must_collect_files = patch("azurelinuxagent.common.logcollector.MUST_COLLECT_FILES_REGEX",
                                            cls.must_collect_files)

        cls.mock_normal_manifest_path.start()
        cls.mock_full_manifest_path.start()
        cls.mock_log_collector_dir.start()
        cls.mock_truncated_files_dir.start()
        cls.mock_output_archive_path.start()
        cls.mock_output_results_file_path.start()
        cls.mock_must_collect_files.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock_normal_manifest_path.stop()
        cls.mock_full_manifest_path.stop()
        cls.mock_log_collector_dir.stop()
        cls.mock_truncated_files_dir.stop()
        cls.mock_output_archive_path.stop()
        cls.mock_output_results_file_path.stop()
        cls.mock_must_collect_files.stop()

        if cls.tmp_dir is not None:
            rm_dirs(cls.tmp_dir)

        AgentTestCase.tearDownClass()

    def setUp(self):
        AgentTestCase.setUp(self)

        self._build_manifest(self.full_manifest_path)

    def tearDown(self):
        rm_dirs(self.log_collector_dir)
        rm_dirs(self.truncated_files_dir)

        AgentTestCase.tearDown(self)

    @classmethod
    def _build_test_data(cls):
        """
        Build a dummy file structure which will be used as a foundation for the log collector tests
        """
        cls.root_collect_dir = os.path.join(cls.tmp_dir, "files_to_collect")
        mkdir(cls.root_collect_dir)

        cls._create_file(os.path.join(cls.root_collect_dir, "waagent.log"), 1 * 1024 * 1024)  # small text file
        cls._create_file(os.path.join(cls.root_collect_dir, "waagent.log.1"), 3 * 1024 * 1024)  # large text file
        cls._create_file(os.path.join(cls.root_collect_dir, "waagent.log.2.gz"), 1 * 1024 * 1024,
                         binary=True)  # small binary file
        cls._create_file(os.path.join(cls.root_collect_dir, "waagent.log.3.gz"), 3 * 1024 * 1024,
                         binary=True)  # large binary file

        cls._create_file(os.path.join(cls.root_collect_dir, "less_important_file"), 1 * 1024 * 1024)

    @staticmethod
    def _create_file(file_path, file_size, binary=False):
        binary_descriptor = "b" if binary else ""
        data = b'0' if binary else '0'

        with open(file_path, "w{0}".format(binary_descriptor)) as fh:
            fh.seek(file_size - 1)
            fh.write(data)

    def _assert_files_are_in_archive(self, expected_files):
        with zipfile.ZipFile(self.output_archive_path, "r") as archive:
            archive_files = archive.namelist()

            for file in expected_files:
                if file.lstrip(os.path.sep) not in archive_files:
                    self.fail("File {0} was expected to be collected, but is not present in the archive!".format(file))

        self.assertTrue(True)

    def _assert_files_are_not_in_archive(self, unexpected_files):
        with zipfile.ZipFile(self.output_archive_path, "r") as archive:
            archive_files = archive.namelist()

            for file in unexpected_files:
                if file.lstrip(os.path.sep) in archive_files:
                    self.fail("File {0} wasn't expected to be collected, but is present in the archive!".format(file))

        self.assertTrue(True)

    def _build_manifest(self, manifest_file):
        files = [
            os.path.join(self.root_collect_dir, "waagent*"),
            os.path.join(self.root_collect_dir, "less_important_file*"),
            os.path.join(self.root_collect_dir, "least_important_file*")
        ]

        with open(manifest_file, "w") as fh:
            for file in files:
                fh.write("copy,{0}\n".format(file))

    def test_log_collector_should_truncate_large_text_files_and_ignore_large_binary_files(self):
        with patch("azurelinuxagent.common.logcollector.FILE_SIZE_LIMIT", 2 * 1024 * 1024):
            lc = LogCollector("full")
            archive = lc.collect_logs()

        # expected files in archive
        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.truncated_files_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "waagent.log.3.gz")
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        self.assertIsNotNone(archive)

    def test_log_collector_should_prioritize_files_if_archive_too_big(self):
        with patch("azurelinuxagent.common.logcollector.ARCHIVE_SIZE_LIMIT", 8 * 1024 * 1024):
            lc = LogCollector("full")
            archive = lc.collect_logs()

        expected_files = [
            os.path.join(self.root_collect_dir, "waagent.log"),
            os.path.join(self.root_collect_dir, "waagent.log.1"),
            os.path.join(self.root_collect_dir, "waagent.log.2.gz"),
            os.path.join(self.root_collect_dir, "waagent.log.3.gz")
        ]
        unexpected_files = [
            os.path.join(self.root_collect_dir, "less_important_file")
        ]
        self._assert_files_are_in_archive(expected_files)
        self._assert_files_are_not_in_archive(unexpected_files)

        self.assertIsNotNone(archive)
