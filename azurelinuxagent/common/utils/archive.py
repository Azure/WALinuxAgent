# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import errno
import os
import re
import shutil
import zipfile

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
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

ARCHIVE_DIRECTORY_NAME = 'history'

_MAX_ARCHIVED_STATES = 50

_CACHE_PATTERNS = [
    re.compile(r"^VmSettings.\d+\.json$"),
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE),
    re.compile(r"waagent_status\.(\d+)\.json$")
]

_GOAL_STATE_PATTERN = re.compile(r"^(.*)/GoalState\.(\d+)\.xml$", re.IGNORECASE)

# Old names didn't have incarnation, new ones do. Ensure the regex captures both cases.
# 2018-04-06T08:21:37.142697_incarnation_N
# 2018-04-06T08:21:37.142697_incarnation_N.zip
_ARCHIVE_PATTERNS_DIRECTORY = re.compile(r"^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(_incarnation_(\d+))?$$")
_ARCHIVE_PATTERNS_ZIP = re.compile(r"^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(_incarnation_(\d+))?\.zip$")

_GOAL_STATE_FILE_NAME = "GoalState.{0}.xml"
_VM_SETTINGS_FILE_NAME = "VmSettings.json"
_HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
_SHARED_CONF_FILE_NAME = "SharedConfig.xml"
_REMOTE_ACCESS_FILE_NAME = "RemoteAccess.{0}.xml"
_EXT_CONF_FILE_NAME = "ExtensionsConfig.{0}.xml"
_MANIFEST_FILE_NAME = "{0}.{1}.manifest.xml"


# TODO: use @total_ordering once RHEL/CentOS and SLES 11 are EOL.
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

        ziph = None
        try:
            # contextmanager for zipfile.ZipFile doesn't exist for py2.6, manually closing it
            ziph = zipfile.ZipFile(fn_tmp, 'w')
            for current_file in os.listdir(self._path):
                full_path = os.path.join(self._path, current_file)
                ziph.write(full_path, current_file, zipfile.ZIP_DEFLATED)
        finally:
            if ziph is not None:
                ziph.close()

        os.rename(fn_tmp, filename)
        shutil.rmtree(self._path)


class StateArchiver(object):
    def __init__(self, lib_dir):
        self._source = os.path.join(lib_dir, ARCHIVE_DIRECTORY_NAME)

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


class GoalStateHistory(object):
    def __init__(self, timestamp, tag):
        self._errors = False
        self._root = os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME, "{0}_{1}".format(timestamp, tag))

    def _save(self, data, file_name):
        try:
            if not os.path.exists(self._root):
                fileutil.mkdir(self._root, mode=0o700)
            full_file_name = os.path.join(self._root, file_name)
            fileutil.write_file(full_file_name, data)
        except IOError as e:
            if not self._errors:  # report only 1 error per directory
                self._errors = True
                logger.warn("Failed to save goal state file {0}: {1} [no additional errors saving the goal state will be reported]".format(file_name, e))

    def save_goal_state(self, text, incarnation):
        self._save(text, _GOAL_STATE_FILE_NAME.format(incarnation))

    def save_extensions_config(self, text, incarnation):
        self._save(text, _EXT_CONF_FILE_NAME.format(incarnation))

    def save_vm_settings(self, text):
        self._save(text, _VM_SETTINGS_FILE_NAME)

    def save_remote_access(self, text, incarnation):
        self._save(text, _REMOTE_ACCESS_FILE_NAME.format(incarnation))

    def save_hosting_env(self, text):
        self._save(text, _HOSTING_ENV_FILE_NAME)

    def save_shared_conf(self, text):
        self._save(text, _SHARED_CONF_FILE_NAME)

