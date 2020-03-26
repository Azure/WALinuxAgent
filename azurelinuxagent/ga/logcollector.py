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
import os

from azurelinuxagent.common.utils.fileutil import read_file, rm_files, rm_dirs, append_file
from azurelinuxagent.common.utils.shellutil import run_command
import azurelinuxagent.common.logger as logger

level = logger.LogLevel.INFO
# logger.add_logger_appender(logger.AppenderType.FILE, level, path="/home/pagombar/waagent.log")log

NORMAL_COLLECTION_MANIFEST_PATH = '/home/paula/manifest-normal'
FULL_COLLECTION_MANIFEST_PATH = '/home/paula/manifest-full'
OUTPUT_ARCHIVE_PATH = '/home/paula/archive.zip'
OUTPUT_RESULTS_FILE_PATH = '/home/paula/results.txt'
TEMPORARY_DIR = '/home/paula/log-tmp'

FILE_SIZE_LIMIT = 30 * 1024 * 1024  # 30 MB
ARCHIVE_SIZE_LIMIT = 150 * 1024 * 1024  # 150 MB


class LogCollector(object):

    def __init__(self, collection_mode="normal"):
        self.collection_mode = collection_mode
        self.manifest_file_path = FULL_COLLECTION_MANIFEST_PATH if collection_mode == "full" else \
            NORMAL_COLLECTION_MANIFEST_PATH

    def _read_manifest_file(self):
        return read_file(self.manifest_file_path).splitlines()

    @staticmethod
    def _clear_file(file_path):
        if os.path.exists(file_path):
            os.remove(file_path)

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
        # The entry either needs expanding, e.g. '/var/log/azure/*',
        # or points ot a file, e.g. '/var/lib/waagent/HostingEnvironmentConfig.xml'
        files = set()

        if os.path.exists(path):
            files.add(path)
        else:
            paths = glob.glob(path)
            if len(paths) > 0:
                files.update(paths)

        LogCollector._append_entries_to_file(files, OUTPUT_RESULTS_FILE_PATH)
        return files

    def _parse_manifest_file(self):
        self._clear_file(OUTPUT_RESULTS_FILE_PATH)

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
    def _keep_file_entry(file_path):
        # TODO: add exception handling here
        # try:
        # except OSError
        return os.path.exists(file_path) and os.path.getsize(
            file_path) <= FILE_SIZE_LIMIT and file_path != OUTPUT_ARCHIVE_PATH

    @staticmethod
    def _truncate_large_file(file_path):
        # Truncate large file to size limit (keep freshest entries), copy file to a temporary location and update
        # file path in list of files to collect

        # tail -c N will output the last N bytes of a file
        pass

    @staticmethod
    def _reduce_archive_size():
        # Remove low priority files iteratively while archive size is too large
        # idea: old waagent logs first? syslog? sort by (size, age) and start from the top?
        pass

    def _get_list_of_files_to_collect(self):
        files_to_collect = self._parse_manifest_file()

        # handle large files here

        files_to_collect.add(OUTPUT_RESULTS_FILE_PATH)
        return filter(self._keep_file_entry, files_to_collect)

    @staticmethod
    def _append_entries_to_file(entries, file_path):
        out = open(file_path, 'a+')
        for entry in entries:
            out.write(entry + "\n")

        out.close()

    @staticmethod
    def _create_list_file(files_to_collect):
        # save to a file to use as input for zip
        tmp_file_path = os.path.join('/var/lib/waagent', 'files.lst')
        LogCollector._clear_file(tmp_file_path)
        LogCollector._append_entries_to_file(files_to_collect, tmp_file_path)
        return tmp_file_path

    @staticmethod
    def _cleanup():
        rm_dirs(TEMPORARY_DIR)

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
            self._cleanup()


lc = LogCollector("full")
archive = lc.collect_logs()
