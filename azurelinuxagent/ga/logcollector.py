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
from azurelinuxagent.common.utils.fileutil import read_file, rm_files, rm_dirs, append_file, mkdir
from azurelinuxagent.common.utils.shellutil import run_command
import azurelinuxagent.common.logger as logger

level = logger.LogLevel.INFO

NORMAL_COLLECTION_MANIFEST_PATH = '/home/paula/manifest-normal'
FULL_COLLECTION_MANIFEST_PATH = '/home/paula/manifest-full'
OUTPUT_ARCHIVE_PATH = '/home/paula/archive.zip'
OUTPUT_RESULTS_FILE_PATH = '/home/paula/results.txt'
TEMPORARY_DIR = '/home/paula/log-tmp-truncated'

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

    def __init__(self, collection_mode="normal"):
        self.collection_mode = collection_mode
        self.manifest_file_path = FULL_COLLECTION_MANIFEST_PATH if collection_mode == "full" else \
            NORMAL_COLLECTION_MANIFEST_PATH
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
    def _expand_path(path):
        # The path either needs expanding, e.g. '/var/log/azure/*',
        # or points ot a file, e.g. '/var/lib/waagent/HostingEnvironmentConfig.xml'
        expanded = []
        if os.path.exists(path):
            expanded.append(path)
        else:
            paths = glob.glob(path)
            if len(paths) > 0:
                expanded.extend(paths)
        return expanded

    @staticmethod
    def _parse_ll_command(folder):
        output = run_command(["ls", "-alF", folder])
        header = "Output of \"ll {0}\":\n".format(folder)
        append_file(OUTPUT_RESULTS_FILE_PATH, header + output + "\n")

    @staticmethod
    def _parse_echo_command(message):
        append_file(OUTPUT_RESULTS_FILE_PATH, message + "\n")

    @staticmethod
    def _parse_copy_command(path):
        files = LogCollector._expand_path(path)
        LogCollector._append_entries_to_file(files, OUTPUT_RESULTS_FILE_PATH)
        return files

    def _parse_manifest_file(self):
        rm_files(OUTPUT_RESULTS_FILE_PATH)

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
        # Truncate large file to size limit (keep freshest entries), copy file to a temporary location and update
        # file path in list of files to collect
        if os.path.getsize(file_path) <= FILE_SIZE_LIMIT:
            return file_path

        try:
            # Binary filed cannot be truncated
            if os.path.splitext(file_path)[1] == ".gz":
                return None

            print("file too big: {0}".format(file_path))

            new_file_name = file_path.replace(os.path.sep, "_")
            truncated_file_path = os.path.join(TEMPORARY_DIR, new_file_name)
            mkdir(truncated_file_path)
            print("truncated file path: {0}".format(truncated_file_path))

            run_command("tail -c {0} {1} > {2}".format(FILE_SIZE_LIMIT, file_path, truncated_file_path),
                        shell=True)
            return truncated_file_path
        except OSError as e:
            print("EXCEPTION: {0}".format(ustr(e)))
            return None

    def _get_list_of_files_to_collect(self):
        parsed_file_paths = self._parse_manifest_file()
        prioritized_file_paths = self._get_priority_file_queue(parsed_file_paths)
        final_files_to_collect = self._get_final_list_for_archive(prioritized_file_paths)
        return final_files_to_collect

    @staticmethod
    def _append_entries_to_file(entries, file_path):
        out = open(file_path, 'a+')
        for entry in entries:
            out.write(entry + "\n")

        out.close()

    @staticmethod
    def _create_list_file(files_to_collect):
        # save to a file to use as input for zip
        tmp_file_path = os.path.join('/home/paula', 'files.lst')
        rm_files(tmp_file_path)
        LogCollector._append_entries_to_file(files_to_collect, tmp_file_path)
        return tmp_file_path

    @staticmethod
    def _cleanup():
        rm_dirs(TEMPORARY_DIR)

    def _get_file_priority(self, file):
        if file in self.must_collect_files:
            return self.must_collect_files.index(file)
        else:
            return 999999999

    def _get_priority_file_queue(self, file_list):
        priority_file_queue = []
        for file in file_list:
            priority = self._get_file_priority(file)
            heappush(priority_file_queue, (priority, file))

        return priority_file_queue

    def _get_final_list_for_archive(self, priority_file_queue):
        total_uncompressed_size = 0
        files_to_collect = []

        while priority_file_queue:
            file_path = heappop(priority_file_queue)[1]  # (priority, file_path)
            file_size = min(os.path.getsize(file_path), FILE_SIZE_LIMIT)

            if total_uncompressed_size + file_size > ARCHIVE_SIZE_LIMIT:
                print("Archive too big, done with adding files.")
                break

            final_file_path = self._truncate_large_file(file_path)

            if final_file_path:
                files_to_collect.append(final_file_path)

        return files_to_collect

    def collect_logs(self):
        try:
            files_to_collect = self._get_list_of_files_to_collect()
            list_file = self._create_list_file(files_to_collect)

            # TODO: figure out how to reuse run_command without shell=True
            # zip --filesync OUTPUT_ARCHIVE_PATH -@ < zip.lst
            command = "zip --filesync {0} -@ < {1}".format(OUTPUT_ARCHIVE_PATH, list_file)
            output = run_command(command, shell=True)

            print(output)
            logger.info("success")
            return OUTPUT_ARCHIVE_PATH
        finally:
            print("cleanup")
            self._cleanup()


lc = LogCollector("full")
archive = lc.collect_logs()
