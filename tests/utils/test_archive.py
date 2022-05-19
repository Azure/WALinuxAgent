# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import os
import tempfile
import zipfile
from datetime import datetime, timedelta

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils import fileutil, timeutil
from azurelinuxagent.common.utils.archive import StateArchiver, _MAX_ARCHIVED_STATES
from tests.tools import AgentTestCase, patch

debug = False
if os.environ.get('DEBUG') == '1':
    debug = True

# Enable verbose logger to stdout
if debug:
    logger.add_logger_appender(logger.AppenderType.STDOUT,
                               logger.LogLevel.VERBOSE)


class TestArchive(AgentTestCase):
    def setUp(self):
        super(TestArchive, self).setUp()
        prefix = "{0}_".format(self.__class__.__name__)

        self.tmp_dir = tempfile.mkdtemp(prefix=prefix)

    def _write_file(self, filename, contents=None):
        full_name = os.path.join(self.tmp_dir, filename)
        fileutil.mkdir(os.path.dirname(full_name))

        with open(full_name, 'w') as file_handler:
            data = contents if contents is not None else filename
            file_handler.write(data)
            return full_name

    @property
    def history_dir(self):
        return os.path.join(self.tmp_dir, 'history')

    @staticmethod
    def _parse_archive_name(name):
        # Name can be a directory or a zip
        # '0000-00-00T00:00:00.000000_incarnation_0'
        # '0000-00-00T00:00:00.000000_incarnation_0.zip'
        timestamp_str, incarnation_ext = name.split("_incarnation_")
        incarnation_no_ext = os.path.splitext(incarnation_ext)[0]
        return timestamp_str, incarnation_no_ext

    def test_archive_should_zip_all_but_the_latest_goal_state_in_the_history_folder(self):
        test_files = [
            'GoalState.xml',
            'Prod.manifest.xml',
            'Prod.agentsManifest',
            'Microsoft.Azure.Extensions.CustomScript.xml'
        ]

        # these directories match the pattern that StateArchiver.archive() searches for
        test_directories = []
        for i in range(0, 3):
            timestamp = (datetime.utcnow() + timedelta(minutes=i)).isoformat()
            directory = os.path.join(self.history_dir, "{0}_incarnation_{1}".format(timestamp, i))
            for current_file in test_files:
                self._write_file(os.path.join(directory, current_file))
            test_directories.append(directory)

        test_subject = StateArchiver(self.tmp_dir)
        # NOTE: StateArchiver sorts the state directories by creation time, but the test files are created too fast and the
        # time resolution is too coarse, so instead we mock getctime to simply return the path of the file
        with patch("azurelinuxagent.common.utils.archive.os.path.getctime", side_effect=lambda path: path):
            test_subject.archive()

        for directory in test_directories[0:2]:
            zip_file = directory + ".zip"
            self.assertTrue(os.path.exists(zip_file), "{0} was not archived (could not find {1})".format(directory, zip_file))

            missing_file = self.assert_zip_contains(zip_file, test_files)
            self.assertEqual(None, missing_file, missing_file)

            self.assertFalse(os.path.exists(directory), "{0} was not removed after being archived ".format(directory))

        self.assertTrue(os.path.exists(test_directories[2]), "{0}, the latest goal state, should not have being removed".format(test_directories[2]))

    def test_archive02(self):
        """
        StateArchiver should purge the MAX_ARCHIVED_STATES oldest files
        or directories.  The oldest timestamps are purged first.

        This test case creates a mixture of archive files and directories.
        It creates 5 more values than MAX_ARCHIVED_STATES to ensure that
        5 archives are cleaned up.  It asserts that the files and
        directories are properly deleted from the disk.
        """
        count = 6
        total = _MAX_ARCHIVED_STATES + count

        start = datetime.now()
        timestamps = []

        for i in range(0, total):
            timestamp = start + timedelta(seconds=i)
            timestamps.append(timestamp)

            if i % 2 == 0:
                filename = os.path.join('history', "{0}_0".format(timestamp.isoformat()), 'Prod.manifest.xml')
            else:
                filename = os.path.join('history', "{0}_0.zip".format(timestamp.isoformat()))

            self._write_file(filename)

        self.assertEqual(total, len(os.listdir(self.history_dir)))

        test_subject = StateArchiver(self.tmp_dir)
        # NOTE: StateArchiver sorts the state directories by creation time, but the test files are created too fast and the
        # time resolution is too coarse, so instead we mock getctime to simply return the path of the file
        with patch("azurelinuxagent.common.utils.archive.os.path.getctime", side_effect=lambda path: path):
            test_subject.purge()

        archived_entries = os.listdir(self.history_dir)
        self.assertEqual(_MAX_ARCHIVED_STATES, len(archived_entries))

        archived_entries.sort()

        for i in range(0, _MAX_ARCHIVED_STATES):
            timestamp = timestamps[i + count].isoformat()
            if i % 2 == 0:
                filename = "{0}_0".format(timestamp)
            else:
                filename = "{0}_0.zip".format(timestamp)
            self.assertTrue(filename in archived_entries, "'{0}' is not in the list of unpurged entires".format(filename))

    def test_purge_legacy_goal_state_history(self):
        with patch("azurelinuxagent.common.conf.get_lib_dir", return_value=self.tmp_dir):
            legacy_files = [
                'GoalState.2.xml',
                'VmSettings.2.json',
                'Prod.2.manifest.xml',
                'ExtensionsConfig.2.xml',
                'Microsoft.Azure.Extensions.CustomScript.1.xml',
                'SharedConfig.xml',
                'HostingEnvironmentConfig.xml',
                'RemoteAccess.xml',
                'waagent_status.1.json'
            ]
            legacy_files = [os.path.join(self.tmp_dir, f) for f in legacy_files]
            for f in legacy_files:
                self._write_file(f)

            StateArchiver.purge_legacy_goal_state_history()

            for f in legacy_files:
                self.assertFalse(os.path.exists(f), "Legacy file {0} was not removed".format(f))

    def test_archive03(self):
        """
        All archives should be purged, both with the legacy naming (with incarnation number) and with the new naming.
        """
        start = datetime.now()
        timestamp1 = start + timedelta(seconds=5)
        timestamp2 = start + timedelta(seconds=10)
        timestamp3 = start + timedelta(seconds=10)

        dir_old = timestamp1.isoformat()
        dir_new = "{0}_incarnation_1".format(timestamp2.isoformat())

        archive_old = "{0}.zip".format(timestamp1.isoformat())
        archive_new = "{0}_incarnation_1.zip".format(timestamp2.isoformat())

        status = "{0}.zip".format(timestamp3.isoformat())

        self._write_file(os.path.join("history", dir_old, "Prod.manifest.xml"))
        self._write_file(os.path.join("history", dir_new, "Prod.manifest.xml"))
        self._write_file(os.path.join("history", archive_old))
        self._write_file(os.path.join("history", archive_new))
        self._write_file(os.path.join("history", status))

        self.assertEqual(5, len(os.listdir(self.history_dir)), "Not all entries were archived!")

        test_subject = StateArchiver(self.tmp_dir)
        with patch("azurelinuxagent.common.utils.archive._MAX_ARCHIVED_STATES", 0):
            test_subject.purge()

        archived_entries = os.listdir(self.history_dir)
        self.assertEqual(0, len(archived_entries), "Not all entries were purged!")

    def test_archive04(self):
        """
        The archive directory is created if it does not exist.

        This failure was caught when .purge() was called before .archive().
        """
        test_subject = StateArchiver(os.path.join(self.tmp_dir, 'does-not-exist'))
        test_subject.purge()

    @staticmethod
    def parse_isoformat(timestamp_str):
        return datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')

    @staticmethod
    def assert_is_iso8601(timestamp_str):
        try:
            TestArchive.parse_isoformat(timestamp_str)
        except:
            raise AssertionError("the value '{0}' is not an ISO8601 formatted timestamp".format(timestamp_str))

    def assert_datetime_close_to(self, time1, time2, within):
        if time1 <= time2:
            diff = time2 - time1
        else:
            diff = time1 - time2

        secs = timeutil.total_seconds(within - diff)
        if secs < 0:
            self.fail("the timestamps are outside of the tolerance of by {0} seconds".format(secs))

    @staticmethod
    def assert_zip_contains(zip_filename, files):

        ziph = None
        try:
            # contextmanager for zipfile.ZipFile doesn't exist for py2.6, manually closing it
            ziph = zipfile.ZipFile(zip_filename, 'r')
            zip_files = [x.filename for x in ziph.filelist]
            for current_file in files:
                if current_file not in zip_files:
                    return "'{0}' was not found in {1}".format(current_file, zip_filename)
            return None
        finally:
            if ziph is not None:
                ziph.close()