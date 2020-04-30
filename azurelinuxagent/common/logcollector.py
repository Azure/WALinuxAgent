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
import subprocess
import zipfile

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.fileutil import mkdir, read_file, rm_files, append_file, append_items_to_file


_LOG_COLLECTOR_DIR = '/var/lib/waagent/logcollector'
_TRUNCATED_FILES_DIR = '/var/truncated'

_OUTPUT_RESULTS_FILE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "results.txt")
COMPRESSED_ARCHIVE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "logs.zip")

_MUST_COLLECT_FILES = [
    '/var/log/waagent.log',
    '/var/lib/waagent/GoalState.*.xml',
    '/var/lib/waagent/ExtensionsConfig.*.xml',
    '/var/lib/waagent/waagent_status.json',
    '/var/lib/waagent/history/*.zip',
    '/var/log/azure/*/*',
    '/var/log/azure/*/*/*',
    '/var/lib/waagent/HostingEnvironmentConfig.xml',
    '/var/log/waagent*',
]

_FILE_SIZE_LIMIT = 30 * 1024 * 1024  # 30 MB
_UNCOMPRESSED_ARCHIVE_SIZE_LIMIT = 150 * 1024 * 1024  # 150 MB


class LogCollector(object):

    _TRUNCATED_FILE_PREFIX = "truncated_"

    def __init__(self, manifest_file_path):
        self.manifest_file_path = manifest_file_path
        self.must_collect_files = self._expand_must_collect_files()

    @staticmethod
    def run_shell_command(command, stdout=subprocess.PIPE, output=False):
        def format_command(cmd):
            return " ".join(cmd) if isinstance(cmd, list) else command

        def _encode_command_output(output):
            return ustr(output, encoding='utf-8', errors="backslashreplace")

        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=subprocess.PIPE, shell=False)
            stdout, stderr = process.communicate()
            return_code = process.returncode
        except Exception as e:
            error_msg = u"Command [{0}] raised unexpected exception: [{1}]".format(format_command(command), ustr(e))
            LogCollector._log_to_results_file(error_msg)
            return

        if return_code != 0:
            encoded_stdout = _encode_command_output(stdout)
            encoded_stderr = _encode_command_output(stderr)
            error_msg = "Command: [{0}], return code: [{1}], stdout: [{2}] stderr: [{3}]".format(format_command(command),
                                                                                                 return_code,
                                                                                                 encoded_stdout,
                                                                                                 encoded_stderr)
            LogCollector._log_to_results_file(error_msg)
            return

        if output:
            msg = "Output of command [{0}]:\n{1}".format(format_command(command), _encode_command_output(stdout))
            LogCollector._log_to_results_file(msg)

    @staticmethod
    def _expand_must_collect_files():
        # Match the regexes from the MUST_COLLECT_FILES list to existing file paths on disk.
        manifest = []
        for path in _MUST_COLLECT_FILES:
            manifest.extend(sorted(glob.glob(path)))

        return manifest

    def _read_manifest_file(self):
        return read_file(self.manifest_file_path).splitlines()

    @staticmethod
    def _log_to_results_file(entry):
        if isinstance(entry, list):
            append_items_to_file(_OUTPUT_RESULTS_FILE_PATH, entry)
        else:
            append_file(_OUTPUT_RESULTS_FILE_PATH, entry + "\n")

    @staticmethod
    def _process_ll_command(folder):
        LogCollector.run_shell_command(["ls", "-alF", folder], output=True)

    @staticmethod
    def _process_echo_command(message):
        LogCollector._log_to_results_file(message)

    @staticmethod
    def _process_copy_command(path):
        file_paths = glob.glob(path)
        LogCollector._log_to_results_file(file_paths)
        return file_paths

    @staticmethod
    def _convert_file_name_to_archive_name(file_name):
        # File name is the name of the file on disk, whereas archive name is the name of that same file in the archive.
        # For non-truncated files: /var/log/waagent.log on disk becomes var/log/waagent.log in archive
        # (leading separator is removed by the archive).
        # For truncated files: /var/truncated/var/log/syslog.1 on disk becomes truncated_var_log_syslog.1 in archive.
        if file_name.startswith(_TRUNCATED_FILES_DIR):
            original_file_path = file_name[len(_TRUNCATED_FILES_DIR):].lstrip(os.path.sep)
            archive_file_name = LogCollector._TRUNCATED_FILE_PREFIX + original_file_path.replace(os.path.sep, "_")
            return archive_file_name
        else:
            return file_name.lstrip(os.path.sep)

    @staticmethod
    def _remove_uncollected_truncated_files(files_to_collect):
        # After log collection is completed, see if there are any old truncated files which were not collected
        # and remove them since they probably won't be collected in the future. This is possible when the
        # original file got deleted, so there is no need to keep its truncated version anymore.
        truncated_files = os.listdir(_TRUNCATED_FILES_DIR)

        for file_path in truncated_files:
            full_path = os.path.join(_TRUNCATED_FILES_DIR, file_path)
            if full_path not in files_to_collect:
                rm_files(full_path)

    def _parse_manifest_file(self):
        files_to_collect = set()
        manifest_entries = self._read_manifest_file()

        for entry in manifest_entries:
            # The entry can be one of the four flavours:
            # 1) ll,/etc/udev/rules.d -- list out contents of the folder and store to results file
            # 2) echo,### Gathering Configuration Files ### -- print message to results file
            # 3) copy,/var/lib/waagent/provisioned -- add file to list of files to be collected
            # 4) diskinfo, -- ignore commands from manifest other than ll, echo, and copy for now

            contents = entry.split(",")
            if len(contents) != 2:
                # If it's not a comment or an empty line, it's a malformed entry
                if not entry.startswith("#") and len(entry.strip()) > 0:
                    LogCollector._log_to_results_file("Error: couldn't parse \"{0}\"".format(entry))
                continue

            command, value = contents

            if command == "ll":
                self._process_ll_command(value)
            elif command == "echo":
                self._process_echo_command(value)
            elif command == "copy":
                files_to_collect.update(self._process_copy_command(value))

        return files_to_collect

    @staticmethod
    def _truncate_large_file(file_path):
        # Truncate large file to size limit (keep freshest entries of the file), copy file to a temporary location
        # and update file path in list of files to collect
        try:
            # Binary files cannot be truncated, don't include large binary files
            ext = os.path.splitext(file_path)[1]
            if ext in [".gz", ".zip", ".xz"]:
                LogCollector._log_to_results_file("Discarding large binary file {0}".format(file_path))
                return None

            truncated_file_path = os.path.join(_TRUNCATED_FILES_DIR, file_path.replace(os.path.sep, "_"))
            if os.path.exists(truncated_file_path):
                original_file_mtime = os.path.getmtime(file_path)
                truncated_file_mtime = os.path.getmtime(truncated_file_path)

                # If the original file hasn't been updated since the truncated file, it means there were no changes
                # and we don't need to truncate it again.
                if original_file_mtime < truncated_file_mtime:
                    return truncated_file_path

            # Get the last N bytes of the file
            with open(truncated_file_path, "w+") as fh:
                LogCollector.run_shell_command(["tail", "-c", str(_FILE_SIZE_LIMIT), file_path], stdout=fh)

            return truncated_file_path
        except OSError as e:
            LogCollector._log_to_results_file("Failed to truncate large file: {0}".format(ustr(e)))
            return None

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
        self._log_to_results_file("\n### Preparing list of files to add to archive ###")
        total_uncompressed_size = 0
        final_files_to_collect = []

        while priority_file_queue:
            file_path = heappop(priority_file_queue)[1]  # (priority, file_path)
            file_size = min(os.path.getsize(file_path), _FILE_SIZE_LIMIT)

            if total_uncompressed_size + file_size > _UNCOMPRESSED_ARCHIVE_SIZE_LIMIT:
                self._log_to_results_file("Archive too big, done with adding files.")
                break

            if os.path.getsize(file_path) <= _FILE_SIZE_LIMIT:
                final_files_to_collect.append(file_path)
                self._log_to_results_file("Adding file {0}, size {1}b".format(file_path, file_size))
            else:
                truncated_file_path = self._truncate_large_file(file_path)
                if truncated_file_path:
                    self._log_to_results_file("Adding truncated file {0}, size {1}b".format(truncated_file_path, file_size))
                    final_files_to_collect.append(truncated_file_path)

            total_uncompressed_size += file_size

        self._log_to_results_file("Uncompressed archive size is {0}b".format(total_uncompressed_size))

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
        return files_to_collect

    def collect_logs(self):
        """
        Public method that collects necessary log files in a tarball that is updated each time this method is invoked.
        The tarball is then compressed into a zip.
        :return: Returns True if the log collection succeeded
        """
        files_to_collect = []

        try:
            # Clear previous run's output and create base directories if they don't exist already
            rm_files(_OUTPUT_RESULTS_FILE_PATH)
            mkdir(_TRUNCATED_FILES_DIR)
            mkdir(_LOG_COLLECTOR_DIR)

            files_to_collect = self._create_list_of_files_to_collect()
            self._log_to_results_file("\n### Creating compressed archive ###")

            with zipfile.ZipFile(COMPRESSED_ARCHIVE_PATH, "w", compression=zipfile.ZIP_DEFLATED) as compressed_archive:
                for file in files_to_collect:
                    archive_file_name = LogCollector._convert_file_name_to_archive_name(file)
                    compressed_archive.write(file, arcname=archive_file_name)

                compressed_archive_size = os.path.getsize(COMPRESSED_ARCHIVE_PATH)
                self._log_to_results_file("Successfully compressed files. "
                                          "Compressed archive size is {0}b".format(compressed_archive_size))
                compressed_archive.write(_OUTPUT_RESULTS_FILE_PATH, arcname="results.txt")

            return True
        except Exception as e:
            msg = "Failed to collect logs: {0}".format(ustr(e))
            self._log_to_results_file(msg)

            return False
        finally:
            self._remove_uncollected_truncated_files(files_to_collect)
