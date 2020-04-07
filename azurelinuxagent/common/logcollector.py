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

from datetime import datetime
import glob
from heapq import heappush, heappop
import os
import tarfile
import zipfile

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils.fileutil import mkdir, read_file, rm_files, append_file, append_items_to_file
from azurelinuxagent.common.utils.shellutil import run_command
from azurelinuxagent.common.utils.textutil import safe_shlex_split
import azurelinuxagent.common.logger as logger

level = logger.LogLevel.INFO

LOG_COLLECTOR_DIR = '/var/lib/waagent/logcollector'
TRUNCATED_FILES_DIR = '/var/truncated'

OUTPUT_RESULTS_FILE_PATH = os.path.join(LOG_COLLECTOR_DIR, "results.txt")
OUTPUT_ARCHIVE_PATH = os.path.join(LOG_COLLECTOR_DIR, "logs.tar")
COMPRESSED_ARCHIVE_PATH = os.path.join(LOG_COLLECTOR_DIR, "logs.zip")

MUST_COLLECT_FILES = [
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
ARCHIVE_SIZE_LIMIT = 150 * 1024 * 1024  # 150 MB


class LogCollector(object):

    def __init__(self, manifest_file_path):
        self.manifest_file_path = manifest_file_path
        self.must_collect_files = self._expand_must_collect_files()

    def _expand_must_collect_files(self):
        # Match the regexes from the MUST_COLLECT_FILES list to existing file paths on disk.
        manifest = []
        for path in MUST_COLLECT_FILES:
            expanded_paths = self._expand_path(path)
            manifest.extend(expanded_paths)

        return manifest

    def _read_manifest_file(self):
        return read_file(self.manifest_file_path).splitlines()

    @staticmethod
    def _log_to_results_file(entry):
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
        LogCollector._log_to_results_file(header + output)

    @staticmethod
    def _parse_echo_command(message):
        LogCollector._log_to_results_file(message)

    @staticmethod
    def _parse_copy_command(path):
        file_paths = LogCollector._expand_path(path)
        LogCollector._log_to_results_file(file_paths)
        return file_paths

    @staticmethod
    def _convert_file_name_to_archive(file_name):
        if file_name.startswith(TRUNCATED_FILES_DIR):
            # /var/truncated/var/log/syslog.1 becomes truncated_var_log_syslog.1
            original_file_path = file_name[len(TRUNCATED_FILES_DIR):].lstrip(os.path.sep)
            archive_file_name = "truncated_" + original_file_path.replace(os.path.sep, "_")
            return archive_file_name
        else:
            return file_name.lstrip(os.path.sep)

    @staticmethod
    def _convert_archive_name_to_file_name(archive_name):
        truncated_prefix = "truncated_"
        if archive_name.startswith(truncated_prefix):
            # truncated_var_log_syslog.1 becomes /var/truncated/var/log/syslog.1
            file_name = archive_name[len(truncated_prefix):].replace("_", os.path.sep)
            original_file_name = os.path.join(TRUNCATED_FILES_DIR, file_name.lstrip(os.path.sep))
            return original_file_name
        else:
            return os.path.join(os.path.sep, archive_name)

    @staticmethod
    def _remove_uncollected_truncated_files(files_to_collect):
        # After log collection is completed, see if there are any old truncated files which were not collected
        # and remove them since they probably won't be collected in the future. This is possible when the
        # original file got deleted, so there is no need to keep its truncated version anymore.
        truncated_files = os.listdir(TRUNCATED_FILES_DIR)

        for file_path in truncated_files:
            full_path = os.path.join(TRUNCATED_FILES_DIR, file_path)
            if full_path not in files_to_collect:
                rm_files(full_path)

    @staticmethod
    def _is_file_updated(file_name, archive_file):
        # A file is updated if either its size or last modified time changed.
        mtime_tarball = datetime.fromtimestamp(archive_file.mtime).replace(microsecond=0)
        mtime_disk = datetime.fromtimestamp(os.path.getmtime(file_name)).replace(microsecond=0)

        file_size_archive = archive_file.size  # uncompressed file size
        file_size_disk = os.path.getsize(file_name)

        return not (mtime_disk == mtime_tarball and file_size_disk == file_size_archive)

    @staticmethod
    def _get_list_of_files_in_archive():
        with tarfile.open(OUTPUT_ARCHIVE_PATH, "a") as tarball:
            return tarball.getnames()

    @staticmethod
    def _delete_file_from_archive(file):
        try:
            command_string = "tar --file {0} --delete {1}".format(OUTPUT_ARCHIVE_PATH, file)
            command = safe_shlex_split(command_string)
            run_command(command)
        except Exception as e:
            LogCollector._log_to_results_file("Failed to delete file {0} from archive: {1}".format(file, ustr(e)))

    @staticmethod
    def _remove_deleted_files_from_archive(final_list_of_files):
        archive_files = LogCollector._get_list_of_files_in_archive()

        for archive_file in archive_files:
            file_name = LogCollector._convert_archive_name_to_file_name(archive_file)

            if file_name not in final_list_of_files and file_name.lstrip(os.path.sep) not in final_list_of_files:
                LogCollector._log_to_results_file("Updating archive, removing deleted file {0}".format(archive_file))
                LogCollector._delete_file_from_archive(archive_file)

    @staticmethod
    def _add_file_to_archive(file_name, archive_file_name):
        with tarfile.open(OUTPUT_ARCHIVE_PATH, "a") as archive:
            archive.add(file_name, arcname=archive_file_name)

    @staticmethod
    def _get_file_from_archive(archive_file_name):
        with tarfile.open(OUTPUT_ARCHIVE_PATH, "r") as archive:
            try:
                return archive.getmember(archive_file_name)
            except KeyError:
                return None

    @staticmethod
    def _update_files_in_archive(final_list_of_files):
        for file_name in final_list_of_files:
            archive_file_name = LogCollector._convert_file_name_to_archive(file_name)
            archive_file = LogCollector._get_file_from_archive(archive_file_name)

            if archive_file:
                # If file is present in the archive, update it if needed (if time last modified or size is different)
                if LogCollector._is_file_updated(file_name, archive_file):
                    LogCollector._log_to_results_file("Updating archive, updating file {0}".format(archive_file_name))
                    LogCollector._delete_file_from_archive(archive_file_name)
                    LogCollector._add_file_to_archive(file_name, archive_file_name)
                else:
                    pass  # nothing to be done, file is archive is the same as file on disk
            else:
                # File is not present in the archive, add it
                LogCollector._log_to_results_file("Updating archive, adding new file {0}".format(archive_file_name))
                LogCollector._add_file_to_archive(file_name, archive_file_name)

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
                LogCollector._log_to_results_file("Discarding large binary file {0}".format(file_path))
                return None

            truncated_file_path = os.path.join(TRUNCATED_FILES_DIR, file_path.replace(os.path.sep, "_"))
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
            file_size = min(os.path.getsize(file_path), FILE_SIZE_LIMIT)

            if total_uncompressed_size + file_size > ARCHIVE_SIZE_LIMIT:
                self._log_to_results_file("Archive too big, done with adding files.")
                break

            if os.path.getsize(file_path) <= FILE_SIZE_LIMIT:
                final_files_to_collect.append(file_path)
                self._log_to_results_file("Adding file {0}, size {1}b".format(file_path, file_size))
            else:
                truncated_file_path = self._truncate_large_file(file_path)
                if truncated_file_path:
                    self._log_to_results_file("Adding truncated file {0}, size {1}b".format(truncated_file_path, file_size))
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
        return files_to_collect

    def collect_logs(self):
        """
        Public method that collects necessary log files in a tarball that is updated each time this method is invoked.
        The tarball is then compressed into a zip.
        :return: Returns True if the log collection succeeded
        """
        try:
            # Clear previous run's output and create base directories if they don't exist already
            rm_files(OUTPUT_RESULTS_FILE_PATH)
            mkdir(TRUNCATED_FILES_DIR)
            mkdir(LOG_COLLECTOR_DIR)

            files_to_collect = self._create_list_of_files_to_collect()
            self._log_to_results_file("\n### Creating archive ###")

            self._remove_deleted_files_from_archive(files_to_collect)
            self._update_files_in_archive(files_to_collect)

            self._log_to_results_file("\n### Compressing archive ###")
            with zipfile.ZipFile(COMPRESSED_ARCHIVE_PATH, "w", compression=zipfile.ZIP_DEFLATED) as compressed_archive:
                compressed_archive.write(OUTPUT_ARCHIVE_PATH, arcname="logs.tar")

            tar_size = os.path.getsize(OUTPUT_ARCHIVE_PATH)
            zip_size = os.path.getsize(COMPRESSED_ARCHIVE_PATH)
            self._log_to_results_file("Uncompressed archive {0} size: {1}b".format(OUTPUT_ARCHIVE_PATH, tar_size))
            self._log_to_results_file("Compressed archive {0} size: {1}b".format(COMPRESSED_ARCHIVE_PATH, zip_size))

            self._remove_uncollected_truncated_files(files_to_collect)

            return True
        except Exception as e:
            msg = "Failed to collect logs: {0}".format(ustr(e))
            self._log_to_results_file(msg)

            return False
