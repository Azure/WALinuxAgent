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

import zipfile

from datetime import datetime, timedelta

from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.archive import StateFlusher, StateArchiver, MAX_ARCHIVED_STATES
from tests.tools import *

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

    def _write_file(self, fn, contents=None):
        full_name = os.path.join(self.tmp_dir, fn)
        fileutil.mkdir(os.path.dirname(full_name))

        with open(full_name, 'w') as fh:
            data = contents if contents is not None else fn
            fh.write(data)
            return full_name

    @property
    def history_dir(self):
        return os.path.join(self.tmp_dir, 'history')

    def test_archive00(self):
        """
        StateFlusher should move all 'goal state' files to a new directory
        under the history folder that is timestamped.
        """
        temp_files = [
            'Prod.0.manifest.xml',
            'Prod.0.agentsManifest',
            'Microsoft.Azure.Extensions.CustomScript.0.xml'
        ]

        for f in temp_files:
            self._write_file(f)

        test_subject = StateFlusher(self.tmp_dir)
        test_subject.flush()

        self.assertTrue(os.path.exists(self.history_dir))
        self.assertTrue(os.path.isdir(self.history_dir))

        timestamp_dirs = os.listdir(self.history_dir)
        self.assertEqual(1, len(timestamp_dirs))

        self.assertIsIso8601(timestamp_dirs[0])
        ts = self.parse_isoformat(timestamp_dirs[0])
        self.assertDateTimeCloseTo(ts, datetime.now(), timedelta(seconds=30))

        for f in temp_files:
            history_path = os.path.join(self.history_dir, timestamp_dirs[0], f)
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
            'Prod.0.manifest.xml',
            'Prod.0.agentsManifest',
            'Microsoft.Azure.Extensions.CustomScript.0.xml'
        ]

        for f in temp_files:
            self._write_file(f)

        flusher = StateFlusher(self.tmp_dir)
        flusher.flush()

        test_subject = StateArchiver(self.tmp_dir)
        test_subject.archive()

        timestamp_zips = os.listdir(self.history_dir)
        self.assertEqual(1, len(timestamp_zips))

        zip_fn = timestamp_zips[0]          # 2000-01-01T00:00:00.000000.zip
        ts_s = os.path.splitext(zip_fn)[0]  # 2000-01-01T00:00:00.000000

        self.assertIsIso8601(ts_s)
        ts = self.parse_isoformat(ts_s)
        self.assertDateTimeCloseTo(ts, datetime.now(), timedelta(seconds=30))

        zip_full = os.path.join(self.history_dir, zip_fn)
        self.assertZipContains(zip_full, temp_files)

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
        total = MAX_ARCHIVED_STATES + count

        start = datetime.now()
        timestamps = []

        for i in range(0, total):
            ts = start + timedelta(seconds=i)
            timestamps.append(ts)

            if i % 2 == 0:
                fn = os.path.join('history', ts.isoformat(), 'Prod.0.manifest.xml')
            else:
                fn = os.path.join('history', "{0}.zip".format(ts.isoformat()))

            self._write_file(fn)

        self.assertEqual(total, len(os.listdir(self.history_dir)))

        test_subject = StateArchiver(self.tmp_dir)
        test_subject.purge()

        archived_entries = os.listdir(self.history_dir)
        self.assertEqual(MAX_ARCHIVED_STATES, len(archived_entries))

        archived_entries.sort()

        for i in range(0, MAX_ARCHIVED_STATES):
            ts = timestamps[i + count].isoformat()
            if i % 2 == 0:
                fn = ts
            else:
                fn = "{0}.zip".format(ts)
            self.assertTrue(fn in archived_entries, "'{0}' is not in the list of unpurged entires".format(fn))

    def parse_isoformat(self, s):
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%f')

    def assertIsIso8601(self, s):
        try:
            self.parse_isoformat(s)
        except:
            raise AssertionError("the value '{0}' is not an ISO8601 formatted timestamp".format(s))

    def assertDateTimeCloseTo(self, t1, t2, within):
        if t1 <= t2:
            diff = t2 -t1
        else:
            diff = t1 - t2

        secs = (within - diff).total_seconds()
        if secs < 0:
            self.fail("the timestamps are outside of the tolerance of by {0} seconds".format(secs))

    def assertZipContains(self, zip_fn, files):
        with zipfile.ZipFile(zip_fn, 'r') as zip:
            zip_files = [x.filename for x in zip.filelist]
            for f in files:
                self.assertTrue(f in zip_files, "'{0}' was not found in {1}".format(f, zip_fn))
