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

import glob
from heapq import heappush, heappop
import os

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.fileutil import mkdir, read_file, rm_files, append_file, append_items_to_file
from azurelinuxagent.common.utils.shellutil import run_command, CommandError
from azurelinuxagent.common.utils.textutil import safe_shlex_split
import azurelinuxagent.common.logger as logger

level = logger.LogLevel.INFO

LOG_COLLECTOR_DIR = '/var/lib/waagent/logcollector'
TRUNCATED_FILES_DIR = '/var/truncated'

OUTPUT_ARCHIVE_PATH = os.path.join(LOG_COLLECTOR_DIR, "logs.zip")
OUTPUT_RESULTS_FILE_PATH = os.path.join(LOG_COLLECTOR_DIR, "results.txt")

MUST_COLLECT_FILES_REGEX = [
    '/var/log/waagent*',
    '/var/lib/waagent/GoalState.*.xml',
    '/var/lib/waagent/waagent_status.json',
    '/var/lib/waagent/history/*.zip',
    '/var/log/azure/*/*',
    '/var/log/azure/*/*/*',
    '/var/lib/waagent/ExtensionsConfig.*.xml',
    '/var/lib/waagent/HostingEnvironmentConfig.xml',
    '/var/lib/waagent/error.json'
]

FILE_SIZE_LIMIT = 30 * 1024 * 1024  # 30 MB

# TODO: determine uncompressed archive size
ARCHIVE_SIZE_LIMIT = 150 * 1024 * 1024  # 150 MB


class LogCollector(object):

    def __init__(self, manifest_file_path):
        self.manifest_file_path = manifest_file_path
        self.must_collect_files = self._expand_must_collect_files()

    def _expand_must_collect_files(self):
        manifest = []
        for path in MUST_COLLECT_FILES_REGEX:
            expanded_paths = self._expand_path(path)
            manifest.extend(expanded_paths)

        return manifest

    def _read_manifest_file(self):
        return read_file(self.manifest_file_path).splitlines()

    @staticmethod
    def _cleanup():
        pass

    @staticmethod
    def log_to_results_file(entry):
        if type(entry) == ustr or type(entry) == str:
            append_file(OUTPUT_RESULTS_FILE_PATH, entry + "\n")
        else:
            append_items_to_file(OUTPUT_RESULTS_FILE_PATH, entry)

    @staticmethod
    def _expand_path(path):
        # If the path needs expanding, e.g. '/var/log/azure/*', add all file matches, sorted by name.
        # Otherwise, add the already expanded path, e.g. '/var/lib/waagent/HostingEnvironmentConfig.xml'
        expanded = []
        if os.path.exists(path):
            expanded.append(path)
        else:
            paths = glob.glob(path)
            if len(paths) > 0:
                expanded.extend(sorted(paths))
        return expanded

    @staticmethod
    def _parse_ll_command(folder):
        output = run_command(["ls", "-alF", folder])
        header = "Output of \"ll {0}\":\n".format(folder)
        LogCollector.log_to_results_file(header + output)

    @staticmethod
    def _parse_echo_command(message):
        LogCollector.log_to_results_file(message)

    @staticmethod
    def _parse_copy_command(path):
        file_paths = LogCollector._expand_path(path)
        LogCollector.log_to_results_file(file_paths)
        return file_paths

    def _parse_manifest_file(self):
        files_to_collect = set()
        manifest_entries = self._read_manifest_file()

        for entry in manifest_entries:
            # The entry can be one of the four flavours:
            # 1) ll,/etc/udev/rules.d -- list out contents of the folder and store to results file
            # 2) echo,### Gathering Configuration Files ### -- print message to results file
            # 3) copy,/var/lib/waagent/provisioned -- add file to list of files to be collected
            # 4) diskinfo, -- ignore other commands for now

            contents = entry.split(",")
            if len(contents) != 2:
                continue

            command, value = entry.split(",")

            if command == "ll":
                self._parse_ll_command(value)
            elif command == "echo":
                self._parse_echo_command(value)
            elif command == "copy":
                files_to_collect.update(self._parse_copy_command(value))

        return files_to_collect

    @staticmethod
    def _truncate_large_file(file_path):
        # Truncate large file to size limit (keep freshest entries of the file), copy file to a temporary location
        # and update file path in list of files to collect
        try:
            # Binary files cannot be truncated, don't include large binary files
            if os.path.splitext(file_path)[1] == ".gz":
                LogCollector.log_to_results_file("Discarding large binary file {0}".format(file_path))
                return None

            new_file_name = os.path.basename(file_path)
            truncated_file_path = os.path.join(TRUNCATED_FILES_DIR, new_file_name)

            if os.path.exists(truncated_file_path):
                original_file_mtime = os.path.getmtime(file_path)
                truncated_file_mtime = os.path.getmtime(truncated_file_path)

                # If the original file hasn't been updated since the truncated file, it means there were no changes
                # and we don't need to truncate it again.
                if original_file_mtime < truncated_file_mtime:
                    return truncated_file_path

            # Get the last N bytes of the file
            with open(truncated_file_path, "w+") as fh:
                command_string = "tail -c {0} {1}".format(FILE_SIZE_LIMIT, file_path)
                command = safe_shlex_split(command_string)
                run_command(command, stdout=fh)

            return truncated_file_path
        except OSError as e:
            LogCollector.log_to_results_file("Failed to truncate large file: {0}".format(ustr(e)))
            return None

    @staticmethod
    def _create_list_file(files_to_collect, file_name):
        tmp_file_path = os.path.join(LOG_COLLECTOR_DIR, file_name)
        rm_files(tmp_file_path)
        append_items_to_file(tmp_file_path, files_to_collect)
        return tmp_file_path

    def _get_file_priority(self, file):
        # The sooner the file appears in the must collect list, the bigger its priority.
        # Priority is higher the lower the number (0 is highest priority).
        if file in self.must_collect_files:
            return self.must_collect_files.index(file)
        else:
            # Doesn't matter, file is not in the must collect list, assign a low priority
            return 999999999

    def _get_priority_files_list(self, file_list):
        # Given a list of files to collect, determine if they show up in the must collect list and build a priority
        # queue. The queue will determine the order in which the files are collected, highest priority files first.
        priority_file_queue = []
        for file in file_list:
            priority = self._get_file_priority(file)
            heappush(priority_file_queue, (priority, file))

        return priority_file_queue

    def _get_final_list_for_archive(self, priority_file_queue):
        # Given a priority queue of files to collect, add one by one while the archive size is under the size limit.
        # If a single file is over the file size limit, truncate it before adding it to the archive.
        self.log_to_results_file("\n### Preparing list of files to add to archive ###")
        total_uncompressed_size = 0
        final_files_to_collect = []

        while priority_file_queue:
            file_path = heappop(priority_file_queue)[1]  # (priority, file_path)
            file_size = min(os.path.getsize(file_path), FILE_SIZE_LIMIT)

            if total_uncompressed_size + file_size > ARCHIVE_SIZE_LIMIT:
                self.log_to_results_file("Archive too big, done with adding files.")
                break

            if os.path.getsize(file_path) <= FILE_SIZE_LIMIT:
                final_files_to_collect.append(file_path)
                self.log_to_results_file("Adding file {0}, size {1}b".format(file_path, file_size))
            else:
                truncated_file_path = self._truncate_large_file(file_path)
                if truncated_file_path:
                    self.log_to_results_file("Adding truncated file {0}, size {1}b".format(truncated_file_path, file_size))
                    final_files_to_collect.append(truncated_file_path)

            total_uncompressed_size += file_size

        return final_files_to_collect

    def _create_list_of_files_to_collect(self):
        # The final list of files to be collected by zip is created in three steps:
        # 1) Parse given manifest file, expanding wildcards and keeping a list of files that exist on disk
        # 2) Assign those files a priority depending on whether they are in the must collect file list.
        # 3) In priority order, add files to the final list to be collected, until the size of the archive is under
        #    the size limit.
        parsed_file_paths = self._parse_manifest_file()
        prioritized_file_paths = self._get_priority_files_list(parsed_file_paths)
        files_to_collect = self._get_final_list_for_archive(prioritized_file_paths)

        files_list = self._create_list_file(files_to_collect, 'files.lst')
        return files_list

    def collect_logs(self):
        try:
            # Clear previous run's output and make base directories if they do not exist already
            rm_files(OUTPUT_RESULTS_FILE_PATH)
            mkdir(TRUNCATED_FILES_DIR)
            mkdir(LOG_COLLECTOR_DIR)

            files_list = self._create_list_of_files_to_collect()
            self.log_to_results_file("\n### Creating archive ###")

            # The --filesync flag of zip synchronizes the contents of an archive with the files on the OS.
            # New files are added, changed files are updated, and removed files are deleted from the archive.
            with open(files_list, "r+") as fh:
                command_string = "zip --filesync {0} -@".format(OUTPUT_ARCHIVE_PATH)
                command = safe_shlex_split(command_string)
                output = run_command(command, stdin=fh)

            LogCollector.log_to_results_file(output)

            return OUTPUT_ARCHIVE_PATH
        except Exception as e:
            stderr = "stderr: {0}".format(e.stderr) if isinstance(e, CommandError) else ""
            msg = "Failed to collect logs: {0} {1}".format(ustr(e), stderr)
            self.log_to_results_file(msg)

            return None
