# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import errno
import os
import re
import shutil
import zipfile
from datetime import datetime

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils import fileutil

# pylint: disable=W0105

"""
archive.py

The module supports the archiving of guest agent state. Guest
agent state is flushed whenever there is a incarnation change.
The flush is archived periodically (once a day).

The process works as follows whenever a new incarnation arrives.

 1. Flush - move all state files to a new directory under
 .../history/timestamp/.
 2. Archive - enumerate all directories under .../history/timestamp
 and create a .zip file named timestamp.zip.  Delete the archive
 directory
 3. Purge - glob the list .zip files, sort by timestamp in descending
 order, keep the first 50 results, and delete the rest.

... is the directory where the agent's state resides, by default this
is /var/lib/waagent.

The timestamp is an ISO8601 formatted value.
"""
# pylint: enable=W0105

_ARCHIVE_DIRECTORY_NAME = 'history'

_MAX_ARCHIVED_STATES = 50

_CACHE_PATTERNS = [
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

_GOAL_STATE_PATTERN = re.compile(r"^(.*)GoalState\.(\d+)\.xml$", re.IGNORECASE)

# 2018-04-06T08:21:37.142697
# 2018-04-06T08:21:37.142697.zip
_ARCHIVE_PATTERNS_DIRECTORY = re.compile(r"^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+$")
_ARCHIVE_PATTERNS_ZIP = re.compile(r"^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\.zip$")


class StateFlusher(object):
    def __init__(self, lib_dir):
        self._source = lib_dir

        directory = os.path.join(self._source, _ARCHIVE_DIRECTORY_NAME)
        if not os.path.exists(directory):
            try:
                fileutil.mkdir(directory)
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    logger.error("{0} : {1}", self._source, exception.strerror)

    def flush(self):
        files = self._get_files_to_archive()
        if not files:
            return

        goal_state_timestamp = self._get_latest_timestamp(files)
        if goal_state_timestamp and self._mkdir(goal_state_timestamp):
            self._archive(files, goal_state_timestamp)
        else:
            self._purge(files)

    def history_dir(self, timestamp):
        return os.path.join(self._source, _ARCHIVE_DIRECTORY_NAME, timestamp.isoformat())

    @staticmethod
    def _get_latest_timestamp(files):
        # Get the most recently modified GoalState.*.xml (if there are more than one) and use that timestamp for the archive name.
        latest_timestamp_ms = None
        for current_file in files:
            match = _GOAL_STATE_PATTERN.match(current_file)
            if not match:
                continue

            modification_time_ms = os.path.getmtime(current_file)
            if not latest_timestamp_ms or latest_timestamp_ms < modification_time_ms:
                latest_timestamp_ms = modification_time_ms

        return datetime.utcfromtimestamp(latest_timestamp_ms)

    def _get_files_to_archive(self):
        files = []
        for current_file in os.listdir(self._source):
            full_path = os.path.join(self._source, current_file)
            for pattern in _CACHE_PATTERNS:
                match = pattern.match(current_file)
                if match is not None:
                    files.append(full_path)
                    break

        return files

    def _archive(self, files, timestamp):
        for current_file in files:
            dst = os.path.join(self.history_dir(timestamp), os.path.basename(current_file))
            shutil.move(current_file, dst)

    def _purge(self, files):
        for current_file in files:
            os.remove(current_file)

    def _mkdir(self, timestamp):
        directory = self.history_dir(timestamp)

        try:
            fileutil.mkdir(directory, mode=0o700)
            return True
        except IOError as exception:
            logger.error("{0} : {1}".format(directory, exception.strerror))
            return False


# TODO: use @total_ordering once RHEL/CentOS and SLES 11 are EOL. # pylint: disable=W0511
# @total_ordering first appeared in Python 2.7 and 3.2
# If there are more use cases for @total_ordering, I will
# consider re-implementing it.
class State(object):
    def __init__(self, path, timestamp):
        self._path = path
        self._timestamp = timestamp

    @property
    def timestamp(self):
        return self._timestamp

    def delete(self):
        pass

    def archive(self):
        pass

    def __eq__(self, other):
        return self._timestamp == other.timestamp

    def __ne__(self, other):
        return self._timestamp != other.timestamp

    def __lt__(self, other):
        return self._timestamp < other.timestamp

    def __gt__(self, other):
        return self._timestamp > other.timestamp

    def __le__(self, other):
        return self._timestamp <= other.timestamp

    def __ge__(self, other):
        return self._timestamp >= other.timestamp


class StateZip(State):
    def delete(self):
        os.remove(self._path)


class StateDirectory(State):
    def delete(self):
        shutil.rmtree(self._path)

    def archive(self):
        fn_tmp = "{0}.zip.tmp".format(self._path)
        filename = "{0}.zip".format(self._path)

        ziph = zipfile.ZipFile(fn_tmp, 'w')
        for current_file in os.listdir(self._path):
            full_path = os.path.join(self._path, current_file)
            ziph.write(full_path, current_file, zipfile.ZIP_DEFLATED)

        ziph.close()

        os.rename(fn_tmp, filename)
        shutil.rmtree(self._path)


class StateArchiver(object):
    def __init__(self, lib_dir):
        self._source = os.path.join(lib_dir, _ARCHIVE_DIRECTORY_NAME)

        if not os.path.isdir(self._source):
            try:
                fileutil.mkdir(self._source, mode=0o700)
            except IOError as exception:
                if exception.errno != errno.EEXIST:
                    logger.error("{0} : {1}", self._source, exception.strerror)

    def purge(self):
        """
        Delete "old" archive directories and .zip archives.  Old
        is defined as any directories or files older than the X
        newest ones.
        """
        states = self._get_archive_states()
        states.sort(reverse=True)

        for state in states[_MAX_ARCHIVED_STATES:]:
            state.delete()

    def archive(self):
        states = self._get_archive_states()
        for state in states:
            state.archive()

    def _get_archive_states(self):
        states = []
        for current_file in os.listdir(self._source):
            full_path = os.path.join(self._source, current_file)
            match = _ARCHIVE_PATTERNS_DIRECTORY.match(current_file)
            if match is not None:
                states.append(StateDirectory(full_path, match.group(0)))

            match = _ARCHIVE_PATTERNS_ZIP.match(current_file)
            if match is not None:
                states.append(StateZip(full_path, match.group(0)))

        return states
