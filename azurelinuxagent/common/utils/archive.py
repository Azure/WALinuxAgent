# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
import re
import shutil
import zipfile

from datetime import datetime

from azurelinuxagent.common.utils import fileutil


"""
archive.py

The module supports the archiving of guest agent state. Guest
agent state is flushed whenever there is a incarnation change.
The flush is archived periodically (once an hour).

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

MAX_ARCHIVED_STATES = 50

CACHE_PATTERNS = [
    re.compile("^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile("^(.*)\.(\d+)\.(xml)$", re.IGNORECASE)
]

# 2018-04-06T08:21:37.142697
# 2018-04-06T08:21:37.142697.zip
ARCHIVE_PATTERNS_DIRECTORY = re.compile('^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+$')
ARCHIVE_PATTERNS_ZIP       = re.compile('^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\.zip$')


class StateFlusher(object):
    def __init__(self, lib_dir):
        self._timestamp = datetime.now()
        self._source = lib_dir
        self._target = os.path.join(self._source, 'history', self._timestamp.isoformat())

    def flush(self):
        files = self._get_files_to_archive()
        if len(files) == 0:
            return

        if self._mkdir():
            self._archive(files)
        else:
            self._purge(files)

    def _get_files_to_archive(self):
        files = []
        for f in os.listdir(self._source):
            full_path = os.path.join(self._source, f)
            for pattern in CACHE_PATTERNS:
                m = pattern.match(f)
                if m is not None:
                    files.append(full_path)
                    break

        return files

    def _archive(self, files):
        for file in files:
            fileutil.move_file(file, to_dir=self._target)

    def _purge(self, files):
        for file in files:
            os.remove(file)

    def _mkdir(self):
        try:
            fileutil.mkdir(self._target, mode=0o700)
            return True
        except:
            return False


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
        return self._timestamp >=  other.timestamp


class StateZip(State):
    def __init__(self, path, timestamp):
        super(StateZip,self).__init__(path, timestamp)

    def delete(self):
        os.remove(self._path)

    def archive(self):
        pass


class StateDirectory(State):
    def __init__(self, path, timestamp):
        super(StateDirectory, self).__init__(path, timestamp)

    def delete(self):
        shutil.rmtree(self._path)

    def archive(self):
        fn_tmp = "{0}.zip.tmp".format(self._path)
        fn = "{0}.zip".format(self._path)

        with zipfile.ZipFile(fn_tmp, 'w') as zip:
            for f in os.listdir(self._path):
                full_path = os.path.join(self._path, f)
                zip.write(full_path, f, zipfile.ZIP_DEFLATED)

        os.rename(fn_tmp, fn)
        shutil.rmtree(self._path)


class StateArchiver(object):
    def __init__(self, lib_dir):
        self._source = os.path.join(lib_dir, 'history')

    def purge(self):
        """
        Delete "old" archive directories and .zip archives.  Old
        is defined as any directories or files older than the X
        newest ones.
        """
        states = self._get_archive_states()
        states.sort(reverse=True)

        for state in states[MAX_ARCHIVED_STATES:]:
            state.delete()

    def archive(self):
        states = self._get_archive_states()
        for state in states:
            state.archive()

    def _get_archive_states(self):
        states = []
        for f in os.listdir(self._source):
            full_path = os.path.join(self._source, f)
            m = ARCHIVE_PATTERNS_DIRECTORY.match(f)
            if m is not None:
                states.append(StateDirectory(full_path, m.group(0)))

            m = ARCHIVE_PATTERNS_ZIP.match(f)
            if m is not None:
                states.append(StateZip(full_path, m.group(0)))

        return states
