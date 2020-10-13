# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import errno
import os
import re
import shutil
import zipfile

from azurelinuxagent.common.utils import fileutil

import azurelinuxagent.common.logger as logger


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

ARCHIVE_DIRECTORY_NAME = 'history'

MAX_ARCHIVED_STATES = 50

CACHE_PATTERNS = [
    re.compile("^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE), # pylint: disable=W1401
    re.compile("^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE), # pylint: disable=W1401
    re.compile("^(.*)\.(\d+)\.(xml)$", re.IGNORECASE) # pylint: disable=W1401
]

# 2018-04-06T08:21:37.142697
# 2018-04-06T08:21:37.142697.zip
ARCHIVE_PATTERNS_DIRECTORY = re.compile('^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+$') # pylint: disable=W1401
ARCHIVE_PATTERNS_ZIP       = re.compile('^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\.zip$') # pylint: disable=W1401


class StateFlusher(object):
    def __init__(self, lib_dir):
        self._source = lib_dir

        d = os.path.join(self._source, ARCHIVE_DIRECTORY_NAME) # pylint: disable=C0103
        if not os.path.exists(d):
            try:
                fileutil.mkdir(d)
            except OSError as e: # pylint: disable=C0103
                if e.errno != errno.EEXIST:
                    logger.error("{0} : {1}", self._source, e.strerror)

    def flush(self, timestamp):
        files = self._get_files_to_archive()
        if len(files) == 0: # pylint: disable=len-as-condition
            return

        if self._mkdir(timestamp):
            self._archive(files, timestamp)
        else:
            self._purge(files)

    def history_dir(self, timestamp):
        return os.path.join(self._source, ARCHIVE_DIRECTORY_NAME, timestamp.isoformat())

    def _get_files_to_archive(self):
        files = []
        for f in os.listdir(self._source): # pylint: disable=C0103
            full_path = os.path.join(self._source, f)
            for pattern in CACHE_PATTERNS:
                m = pattern.match(f) # pylint: disable=C0103
                if m is not None:
                    files.append(full_path)
                    break

        return files

    def _archive(self, files, timestamp):
        for f in files: # pylint: disable=C0103
            dst = os.path.join(self.history_dir(timestamp), os.path.basename(f))
            shutil.move(f, dst)

    def _purge(self, files):
        for f in files: # pylint: disable=C0103
            os.remove(f)

    def _mkdir(self, timestamp):
        d = self.history_dir(timestamp) # pylint: disable=C0103

        try:
            fileutil.mkdir(d, mode=0o700)
            return True
        except IOError as e: # pylint: disable=C0103
            logger.error("{0} : {1}".format(d, e.strerror))
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
    def __init__(self, path, timestamp): # pylint: disable=W0235
        super(StateZip,self).__init__(path, timestamp)

    def delete(self):
        os.remove(self._path)


class StateDirectory(State):
    def __init__(self, path, timestamp): # pylint: disable=W0235
        super(StateDirectory, self).__init__(path, timestamp)

    def delete(self):
        shutil.rmtree(self._path)

    def archive(self):
        fn_tmp = "{0}.zip.tmp".format(self._path)
        fn = "{0}.zip".format(self._path) # pylint: disable=C0103

        ziph = zipfile.ZipFile(fn_tmp, 'w')
        for f in os.listdir(self._path): # pylint: disable=C0103
            full_path = os.path.join(self._path, f)
            ziph.write(full_path, f, zipfile.ZIP_DEFLATED)

        ziph.close()

        os.rename(fn_tmp, fn)
        shutil.rmtree(self._path)


class StateArchiver(object):
    def __init__(self, lib_dir):
        self._source = os.path.join(lib_dir, ARCHIVE_DIRECTORY_NAME)

        if not os.path.isdir(self._source):
            try:
                fileutil.mkdir(self._source, mode=0o700)
            except IOError as e: # pylint: disable=C0103
                if e.errno != errno.EEXIST:
                    logger.error("{0} : {1}", self._source, e.strerror)

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
        for f in os.listdir(self._source): # pylint: disable=C0103
            full_path = os.path.join(self._source, f)
            m = ARCHIVE_PATTERNS_DIRECTORY.match(f) # pylint: disable=C0103
            if m is not None:
                states.append(StateDirectory(full_path, m.group(0)))

            m = ARCHIVE_PATTERNS_ZIP.match(f) # pylint: disable=C0103
            if m is not None:
                states.append(StateZip(full_path, m.group(0)))

        return states
