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
import logging
import os
import subprocess
import time
import zipfile
from datetime import datetime
from heapq import heappush, heappop

from azurelinuxagent.common.conf import get_lib_dir, get_ext_log_dir, get_agent_log_file
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.logcollector_manifests import MANIFEST_NORMAL, MANIFEST_FULL

# Please note: be careful when adding agent dependencies in this module.
# This module uses its own logger and logs to its own file, not to the agent log.

_EXTENSION_LOG_DIR = get_ext_log_dir()
_AGENT_LIB_DIR = get_lib_dir()
_AGENT_LOG = get_agent_log_file()

_LOG_COLLECTOR_DIR = os.path.join(_AGENT_LIB_DIR, "logcollector")
_TRUNCATED_FILES_DIR = os.path.join(_LOG_COLLECTOR_DIR, "truncated")

OUTPUT_RESULTS_FILE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "results.txt")
COMPRESSED_ARCHIVE_PATH = os.path.join(_LOG_COLLECTOR_DIR, "logs.zip")

_MUST_COLLECT_FILES = [
    _AGENT_LOG,
    os.path.join(_AGENT_LIB_DIR, "GoalState.*.xml"),
    os.path.join(_AGENT_LIB_DIR, "ExtensionsConfig.*.xml"),
    os.path.join(_AGENT_LIB_DIR, "HostingEnvironmentConfig.*.xml"),
    os.path.join(_AGENT_LIB_DIR, "SharedConfig.*.xml"),
    os.path.join(_AGENT_LIB_DIR, "*manifest.xml"),
    os.path.join(_AGENT_LIB_DIR, "waagent_status.json"),
    os.path.join(_AGENT_LIB_DIR, "history", "*.zip"),
    os.path.join(_EXTENSION_LOG_DIR, "*", "*"),
    os.path.join(_EXTENSION_LOG_DIR, "*", "*", "*"),
    "{0}.*".format(_AGENT_LOG)  # any additional waagent.log files (e.g., waagent.log.1.gz)
]

_FILE_SIZE_LIMIT = 30 * 1024 * 1024  # 30 MB
_UNCOMPRESSED_ARCHIVE_SIZE_LIMIT = 150 * 1024 * 1024  # 150 MB

_LOGGER = logging.getLogger(__name__)


class LogCollector(object): # pylint: disable=R0903

    _TRUNCATED_FILE_PREFIX = "truncated_"

    def __init__(self, is_full_mode=False):
        self._is_full_mode = is_full_mode
        self._manifest = MANIFEST_FULL if is_full_mode else MANIFEST_NORMAL
        self._must_collect_files = self._expand_must_collect_files()
        self._create_base_dirs()
        self._set_logger()

    @staticmethod
    def _mkdir(dirname):
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

    @staticmethod
    def _reset_file(filepath):
        with open(filepath, "wb") as out_file:
            out_file.write("".encode("utf-8"))

    @staticmethod
    def _create_base_dirs():
        LogCollector._mkdir(_LOG_COLLECTOR_DIR)
        LogCollector._mkdir(_TRUNCATED_FILES_DIR)

    @staticmethod
    def _set_logger():
        _f_handler = logging.FileHandler(OUTPUT_RESULTS_FILE_PATH, encoding="utf-8")
        _f_format = logging.Formatter(fmt='%(asctime)s %(levelname)s %(message)s',
                                      datefmt=u'%Y-%m-%dT%H:%M:%SZ')
        _f_format.converter = time.gmtime
        _f_handler.setFormatter(_f_format)
        _LOGGER.addHandler(_f_handler)
        _LOGGER.setLevel(logging.INFO)

    @staticmethod
    def _run_shell_command(command, stdout=subprocess.PIPE, log_output=False):
        """
        Runs a shell command in a subprocess, logs any errors to the log file, enables changing the stdout stream,
        and logs the output of the command to the log file if indicated by the `log_output` parameter.
        :param command: Shell command to run
        :param stdout: Where to write the output of the command
        :param log_output: If true, log the command output to the log file
        """
        def format_command(cmd):
            return " ".join(cmd) if isinstance(cmd, list) else command

        def _encode_command_output(output):
            return ustr(output, encoding="utf-8", errors="backslashreplace")

        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=subprocess.PIPE, shell=False)
            stdout, stderr = process.communicate()
            return_code = process.returncode
        except Exception as e: # pylint: disable=C0103
            error_msg = u"Command [{0}] raised unexpected exception: [{1}]".format(format_command(command), ustr(e))
            _LOGGER.error(error_msg)
            return

        if return_code != 0:
            encoded_stdout = _encode_command_output(stdout)
            encoded_stderr = _encode_command_output(stderr)
            error_msg = "Command: [{0}], return code: [{1}], stdout: [{2}] stderr: [{3}]".format(format_command(command),
                                                                                                 return_code,
                                                                                                 encoded_stdout,
                                                                                                 encoded_stderr)
            _LOGGER.error(error_msg)
            return

        if log_output:
            msg = "Output of command [{0}]:\n{1}".format(format_command(command), _encode_command_output(stdout))
            _LOGGER.info(msg)

    @staticmethod
    def _expand_must_collect_files():
        # Match the regexes from the MUST_COLLECT_FILES list to existing file paths on disk.
        manifest = []
        for path in _MUST_COLLECT_FILES:
            manifest.extend(sorted(glob.glob(path)))

        return manifest

    def _read_manifest(self):
        return self._manifest.splitlines()

    @staticmethod
    def _process_ll_command(folder):
        LogCollector._run_shell_command(["ls", "-alF", folder], log_output=True)

    @staticmethod
    def _process_echo_command(message):
        _LOGGER.info(message)

    @staticmethod
    def _process_copy_command(path):
        file_paths = glob.glob(path)
        for file_path in file_paths:
            _LOGGER.info(file_path)
        return file_paths

    @staticmethod
    def _convert_file_name_to_archive_name(file_name):
        # File name is the name of the file on disk, whereas archive name is the name of that same file in the archive.
        # For non-truncated files: /var/log/waagent.log on disk becomes var/log/waagent.log in archive
        # (leading separator is removed by the archive).
        # For truncated files: /var/lib/waagent/logcollector/truncated/var/log/syslog.1 on disk becomes
        # truncated_var_log_syslog.1 in the archive.
        if file_name.startswith(_TRUNCATED_FILES_DIR): # pylint: disable=R1705
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
                if os.path.isfile(full_path):
                    os.remove(full_path)

    @staticmethod
    def _expand_parameters(manifest_data):
        _LOGGER.info("Using %s as $LIB_DIR", _AGENT_LIB_DIR)
        _LOGGER.info("Using %s as $LOG_DIR", _EXTENSION_LOG_DIR)
        _LOGGER.info("Using %s as $AGENT_LOG", _AGENT_LOG)

        new_manifest = []
        for line in manifest_data:
            new_line = line.replace("$LIB_DIR", _AGENT_LIB_DIR)
            new_line = new_line.replace("$LOG_DIR", _EXTENSION_LOG_DIR)
            new_line = new_line.replace("$AGENT_LOG", _AGENT_LOG)
            new_manifest.append(new_line)

        return new_manifest

    def _process_manifest_file(self):
        files_to_collect = set()
        data = self._read_manifest()
        manifest_entries = LogCollector._expand_parameters(data)

        for entry in manifest_entries:
            # The entry can be one of the four flavours:
            # 1) ll,/etc/udev/rules.d -- list out contents of the folder and store to results file
            # 2) echo,### Gathering Configuration Files ### -- print message to results file
            # 3) copy,/var/lib/waagent/provisioned -- add file to list of files to be collected
            # 4) diskinfo, -- ignore commands from manifest other than ll, echo, and copy for now

            contents = entry.split(",")
            if len(contents) != 2:
                # If it's not a comment or an empty line, it's a malformed entry
                if not entry.startswith("#") and len(entry.strip()) > 0: # pylint: disable=len-as-condition
                    _LOGGER.error("Couldn't parse \"%s\"", entry)
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
                _LOGGER.warning("Discarding large binary file %s", file_path)
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
            with open(truncated_file_path, "w+") as fh: # pylint: disable=C0103
                LogCollector._run_shell_command(["tail", "-c", str(_FILE_SIZE_LIMIT), file_path], stdout=fh)

            return truncated_file_path
        except OSError as e: # pylint: disable=C0103
            _LOGGER.error("Failed to truncate large file: %s", ustr(e))
            return None

    def _get_file_priority(self, file_entry):
        # The sooner the file appears in the must collect list, the bigger its priority.
        # Priority is higher the lower the number (0 is highest priority).
        try:
            return self._must_collect_files.index(file_entry)
        except ValueError:
            # Doesn't matter, file is not in the must collect list, assign a low priority
            return 999999999

    def _get_priority_files_list(self, file_list):
        # Given a list of files to collect, determine if they show up in the must collect list and build a priority
        # queue. The queue will determine the order in which the files are collected, highest priority files first.
        priority_file_queue = []
        for file_entry in file_list:
            priority = self._get_file_priority(file_entry)
            heappush(priority_file_queue, (priority, file_entry))

        return priority_file_queue

    def _get_final_list_for_archive(self, priority_file_queue):
        # Given a priority queue of files to collect, add one by one while the archive size is under the size limit.
        # If a single file is over the file size limit, truncate it before adding it to the archive.
        _LOGGER.info("### Preparing list of files to add to archive ###")
        total_uncompressed_size = 0
        final_files_to_collect = []

        while priority_file_queue:
            file_path = heappop(priority_file_queue)[1]  # (priority, file_path)
            file_size = min(os.path.getsize(file_path), _FILE_SIZE_LIMIT)

            if total_uncompressed_size + file_size > _UNCOMPRESSED_ARCHIVE_SIZE_LIMIT:
                _LOGGER.warning("Archive too big, done with adding files.")
                break

            if os.path.getsize(file_path) <= _FILE_SIZE_LIMIT:
                final_files_to_collect.append(file_path)
                _LOGGER.info("Adding file %s, size %s b", file_path, file_size)
            else:
                truncated_file_path = self._truncate_large_file(file_path)
                if truncated_file_path:
                    _LOGGER.info("Adding truncated file %s, size %s b", truncated_file_path, file_size)
                    final_files_to_collect.append(truncated_file_path)

            total_uncompressed_size += file_size

        _LOGGER.info("Uncompressed archive size is %s b", total_uncompressed_size)

        return final_files_to_collect

    def _create_list_of_files_to_collect(self):
        # The final list of files to be collected by zip is created in three steps:
        # 1) Parse given manifest file, expanding wildcards and keeping a list of files that exist on disk
        # 2) Assign those files a priority depending on whether they are in the must collect file list.
        # 3) In priority order, add files to the final list to be collected, until the size of the archive is under
        #    the size limit.
        parsed_file_paths = self._process_manifest_file()
        prioritized_file_paths = self._get_priority_files_list(parsed_file_paths)
        files_to_collect = self._get_final_list_for_archive(prioritized_file_paths)
        return files_to_collect

    def collect_logs_and_get_archive(self):
        """
        Public method that collects necessary log files in a compressed zip archive.
        :return: Returns the path of the collected compressed archive
        """
        files_to_collect = []

        try:
            # Clear previous run's output and create base directories if they don't exist already.
            self._create_base_dirs()
            LogCollector._reset_file(OUTPUT_RESULTS_FILE_PATH)
            start_time = datetime.utcnow()
            _LOGGER.info("Starting log collection at %s", start_time.strftime("%Y-%m-%dT%H:%M:%SZ"))
            _LOGGER.info("Using log collection mode %s", "full" if self._is_full_mode else "normal")

            files_to_collect = self._create_list_of_files_to_collect()
            _LOGGER.info("### Creating compressed archive ###")

            with zipfile.ZipFile(COMPRESSED_ARCHIVE_PATH, "w", compression=zipfile.ZIP_DEFLATED) as compressed_archive:
                for file_to_collect in files_to_collect:
                    archive_file_name = LogCollector._convert_file_name_to_archive_name(file_to_collect)
                    compressed_archive.write(file_to_collect.encode("utf-8"), arcname=archive_file_name)

                compressed_archive_size = os.path.getsize(COMPRESSED_ARCHIVE_PATH)
                _LOGGER.info("Successfully compressed files. Compressed archive size is %s b", compressed_archive_size)

                end_time = datetime.utcnow()
                duration = end_time - start_time
                elapsed_ms = int(((duration.days * 24 * 60 * 60 + duration.seconds) * 1000) + (duration.microseconds / 1000.0))
                _LOGGER.info("Finishing log collection at %s", end_time.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
                _LOGGER.info("Elapsed time: %s ms", elapsed_ms)

                compressed_archive.write(OUTPUT_RESULTS_FILE_PATH.encode("utf-8"), arcname="results.txt")

            return COMPRESSED_ARCHIVE_PATH
        except Exception as e: # pylint: disable=C0103
            msg = "Failed to collect logs: {0}".format(ustr(e))
            _LOGGER.error(msg)

            raise
        finally:
            self._remove_uncollected_truncated_files(files_to_collect)
