# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import errno
import glob
import os
import re
import shutil
import zipfile

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.utils import fileutil, timeutil

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

# TODO: See comment in GoalStateHistory._save_placeholder and remove this code when no longer needed
_PLACEHOLDER_FILE_NAME = 'GoalState.1.xml'
# END TODO

_MAX_ARCHIVED_STATES = 50

_CACHE_PATTERNS = [
    re.compile(r"^VmSettings\.\d+\.json$"),
    re.compile(r"^(.*)\.(\d+)\.(agentsManifest)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(manifest\.xml)$", re.IGNORECASE),
    re.compile(r"^(.*)\.(\d+)\.(xml)$", re.IGNORECASE),
    re.compile(r"^SharedConfig\.xml$", re.IGNORECASE),
    re.compile(r"^HostingEnvironmentConfig\.xml$", re.IGNORECASE),
    re.compile(r"^RemoteAccess\.xml$", re.IGNORECASE),
    re.compile(r"^waagent_status\.\d+\.json$"),
]

#
# Legacy names
#   2018-04-06T08:21:37.142697
#   2018-04-06T08:21:37.142697.zip
#   2018-04-06T08:21:37.142697_incarnation_N
#   2018-04-06T08:21:37.142697_incarnation_N.zip
#   2018-04-06T08:21:37.142697_N-M
#   2018-04-06T08:21:37.142697_N-M.zip
#
# Current names
#
#   2018-04-06T08-21-37__N-M
#   2018-04-06T08-21-37__N-M.zip
#
_ARCHIVE_BASE_PATTERN = r"\d{4}\-\d{2}\-\d{2}T\d{2}[:-]\d{2}[:-]\d{2}(\.\d+)?((_incarnation)?_+(\d+|status)(-\d+)?)?"
_ARCHIVE_PATTERNS_DIRECTORY = re.compile(r'^{0}$'.format(_ARCHIVE_BASE_PATTERN))
_ARCHIVE_PATTERNS_ZIP = re.compile(r'^{0}\.zip$'.format(_ARCHIVE_BASE_PATTERN))

_GOAL_STATE_FILE_NAME = "GoalState.xml"
_VM_SETTINGS_FILE_NAME = "VmSettings.json"
_CERTIFICATES_FILE_NAME = "Certificates.json"
_HOSTING_ENV_FILE_NAME = "HostingEnvironmentConfig.xml"
_SHARED_CONF_FILE_NAME = "SharedConfig.xml"
_REMOTE_ACCESS_FILE_NAME = "RemoteAccess.xml"
_EXT_CONF_FILE_NAME = "ExtensionsConfig.xml"
_MANIFEST_FILE_NAME = "{0}.manifest.xml"

AGENT_STATUS_FILE = "waagent_status.json"

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
                    logger.warn("{0} : {1}", self._source, exception.strerror)

    def purge(self):
        """
        Delete "old" archive directories and .zip archives.  Old
        is defined as any directories or files older than the X
        newest ones. Also, clean up any legacy history files.
        """
        states = self._get_archive_states()

        for state in states[_MAX_ARCHIVED_STATES:]:
            state.delete()

    @staticmethod
    def purge_legacy_goal_state_history():
        lib_dir = conf.get_lib_dir()
        for current_file in os.listdir(lib_dir):
            # TODO: See comment in GoalStateHistory._save_placeholder and remove this code when no longer needed
            if current_file == _PLACEHOLDER_FILE_NAME:
                return
            # END TODO
            full_path = os.path.join(lib_dir, current_file)
            for pattern in _CACHE_PATTERNS:
                match = pattern.match(current_file)
                if match is not None:
                    try:
                        os.remove(full_path)
                    except Exception as e:
                        logger.warn("Cannot delete legacy history file '{0}': {1}".format(full_path, e))
                    break

    def archive(self):
        states = self._get_archive_states()

        if len(states) > 0:
            # Skip the most recent goal state, since it may still be in use
            for state in states[1:]:
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

        states.sort(key=lambda state: os.path.getctime(state._path), reverse=True)

        return states


class GoalStateHistory(object):
    def __init__(self, time, tag):
        self._errors = False
        timestamp = timeutil.create_history_timestamp(time)
        self._root = os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME, "{0}__{1}".format(timestamp, tag) if tag is not None else timestamp)

    @staticmethod
    def tag_exists(tag):
        """
        Returns True when an item with the given 'tag' already exists in the history directory
        """
        return len(glob.glob(os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME, "*_{0}".format(tag)))) > 0

    def save(self, data, file_name):
        try:
            if not os.path.exists(self._root):
                fileutil.mkdir(self._root, mode=0o700)
            with open(os.path.join(self._root, file_name), "w") as handle:
                handle.write(data)
        except Exception as e:
            if not self._errors:  # report only 1 error per directory
                self._errors = True
                logger.warn("Failed to save {0} to the goal state history: {1} [no additional errors saving the goal state will be reported]".format(file_name, e))

    @staticmethod
    def _save_placeholder():
        """
        Some internal components took a dependency in the legacy GoalState.*.xml file. We create it here while those components are updated to remove the dependency.
        When removing this code, also remove the check in StateArchiver.purge_legacy_goal_state_history, and the definition of _PLACEHOLDER_FILE_NAME
        """
        try:
            placeholder = os.path.join(conf.get_lib_dir(), _PLACEHOLDER_FILE_NAME)
            with open(placeholder, "w") as handle:
                handle.write("<xml>empty placeholder file</xml>")
        except Exception as e:
            logger.warn("Failed to save placeholder file ({0}): {1}".format(_PLACEHOLDER_FILE_NAME, e))

    def save_goal_state(self, text):
        self.save(text, _GOAL_STATE_FILE_NAME)
        self._save_placeholder()

    def save_extensions_config(self, text):
        self.save(text, _EXT_CONF_FILE_NAME)

    def save_vm_settings(self, text):
        self.save(text, _VM_SETTINGS_FILE_NAME)

    def save_remote_access(self, text):
        self.save(text, _REMOTE_ACCESS_FILE_NAME)

    def save_certificates(self, text):
        self.save(text, _CERTIFICATES_FILE_NAME)

    def save_hosting_env(self, text):
        self.save(text, _HOSTING_ENV_FILE_NAME)

    def save_shared_conf(self, text):
        self.save(text, _SHARED_CONF_FILE_NAME)
