# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import StateFlusher, StateArchiver, _MAX_ARCHIVED_STATES
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
        prefix = "{0}_".format(self.__class__.__name__)

        self.tmp_dir = tempfile.mkdtemp(prefix=prefix)

    def tearDown(self):
        if not debug and self.tmp_dir is not None:
            shutil.rmtree(self.tmp_dir)

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

    def test_archive00(self):
        """
        StateFlusher should move all 'goal state' files to a new directory
        under the history folder that is timestamped.
        """
        temp_files = [
            'GoalState.0.xml',
            'Prod.0.manifest.xml',
            'Prod.0.agentsManifest',
            'Microsoft.Azure.Extensions.CustomScript.0.xml'
        ]

        for temp_file in temp_files:
            self._write_file(temp_file)

        test_subject = StateFlusher(self.tmp_dir)
        test_subject.flush()

        self.assertTrue(os.path.exists(self.history_dir))
        self.assertTrue(os.path.isdir(self.history_dir))

        timestamp_dirs = os.listdir(self.history_dir)
        self.assertEqual(1, len(timestamp_dirs))

        timestamp_str, incarnation = self._parse_archive_name(timestamp_dirs[0])
        self.assert_is_iso8601(timestamp_str)
        timestamp = self.parse_isoformat(timestamp_str)
        self.assert_datetime_close_to(timestamp, datetime.utcnow(), timedelta(seconds=30))
        self.assertEqual("0", incarnation)

        for temp_file in temp_files:
            history_path = os.path.join(self.history_dir, timestamp_dirs[0], temp_file)
            msg = "expected the temp file {0} to exist".format(history_path)
            self.assertTrue(os.path.exists(history_path), msg)

    def test_archive01(self):
        """
        StateArchiver should archive all history directories by

          1. Creating a .zip of a timestamped directory's files
          2. Saving the .zip to /var/lib/waagent/history/
          2. Deleting the timestamped directory
        """
        temp_files = [
            'GoalState.0.xml',
            'Prod.0.manifest.xml',
            'Prod.0.agentsManifest',
            'Microsoft.Azure.Extensions.CustomScript.0.xml'
        ]

        for current_file in temp_files:
            self._write_file(current_file)

        flusher = StateFlusher(self.tmp_dir)
        flusher.flush()

        test_subject = StateArchiver(self.tmp_dir)
        test_subject.archive()

        timestamp_zips = os.listdir(self.history_dir)
        self.assertEqual(1, len(timestamp_zips))

        zip_fn = timestamp_zips[0]  # 2000-01-01T00:00:00.000000_incarnation_N.zip
        timestamp_str, incarnation = self._parse_archive_name(zip_fn)

        self.assert_is_iso8601(timestamp_str)
        timestamp = self.parse_isoformat(timestamp_str)
        self.assert_datetime_close_to(timestamp, datetime.utcnow(), timedelta(seconds=30))
        self.assertEqual("0", incarnation)

        zip_full = os.path.join(self.history_dir, zip_fn)
        self.assert_zip_contains(zip_full, temp_files)

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
                filename = os.path.join('history', "{0}_incarnation_0".format(timestamp.isoformat()), 'Prod.0.manifest.xml')
            else:
                filename = os.path.join('history', "{0}_incarnation_0.zip".format(timestamp.isoformat()))

            self._write_file(filename)

        self.assertEqual(total, len(os.listdir(self.history_dir)))

        test_subject = StateArchiver(self.tmp_dir)
        test_subject.purge()

        archived_entries = os.listdir(self.history_dir)
        self.assertEqual(_MAX_ARCHIVED_STATES, len(archived_entries))

        archived_entries.sort()

        for i in range(0, _MAX_ARCHIVED_STATES):
            timestamp = timestamps[i + count].isoformat()
            if i % 2 == 0:
                filename = "{0}_incarnation_0".format(timestamp)
            else:
                filename = "{0}_incarnation_0.zip".format(timestamp)
            self.assertTrue(filename in archived_entries, "'{0}' is not in the list of unpurged entires".format(filename))

    def test_archive03(self):
        """
        All archives should be purged, both with the new naming (with incarnation number) and with the old naming.
        """
        start = datetime.now()
        timestamp1 = start + timedelta(seconds=5)
        timestamp2 = start + timedelta(seconds=10)

        dir_old = timestamp1.isoformat()
        dir_new = "{0}_incarnation_1".format(timestamp2.isoformat())

        archive_old = "{0}.zip".format(timestamp1.isoformat())
        archive_new = "{0}_incarnation_1.zip".format(timestamp2.isoformat())

        self._write_file(os.path.join("history", dir_old, "Prod.0.manifest.xml"))
        self._write_file(os.path.join("history", dir_new, "Prod.1.manifest.xml"))
        self._write_file(os.path.join("history", archive_old))
        self._write_file(os.path.join("history", archive_new))

        self.assertEqual(4, len(os.listdir(self.history_dir)), "Not all entries were archived!")

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

    @staticmethod
    def _total_seconds(delta):
        """
        Compute the total_seconds for a timedelta because 2.6 does not have total_seconds.
        """
        return (0.0 + delta.microseconds + (delta.seconds + delta.days * 24 * 60 * 60) * 10 ** 6) / 10 ** 6

    def assert_datetime_close_to(self, time1, time2, within):
        if time1 <= time2:
            diff = time2 - time1
        else:
            diff = time1 - time2

        secs = self._total_seconds(within - diff)
        if secs < 0:
            self.fail("the timestamps are outside of the tolerance of by {0} seconds".format(secs))

    def assert_zip_contains(self, zip_filename, files):
        ziph = zipfile.ZipFile(zip_filename, 'r')
        zip_files = [x.filename for x in ziph.filelist]
        for current_file in files:
            self.assertTrue(current_file in zip_files, "'{0}' was not found in {1}".format(current_file, zip_filename))

        ziph.close()
