# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.
import os
import tempfile
import zipfile
from datetime import datetime, timedelta

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import UTC
from azurelinuxagent.common import conf
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.archive import GoalStateHistory, StateArchiver, _MAX_ARCHIVED_STATES, ARCHIVE_DIRECTORY_NAME
from tests.lib.tools import AgentTestCase, patch

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
        full_name = os.path.join(conf.get_lib_dir(), filename)
        fileutil.mkdir(os.path.dirname(full_name))

        with open(full_name, 'w') as file_handler:
            data = contents if contents is not None else filename
            file_handler.write(data)
            return full_name

    @property
    def history_dir(self):
        return os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME)

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
            timestamp = datetime.now(UTC) + timedelta(minutes=i)
            directory = os.path.join(self.history_dir, "{0}__{1}".format(GoalStateHistory._create_timestamp(timestamp), i))
            for current_file in test_files:
                self._write_file(os.path.join(directory, current_file))
            test_directories.append(directory)

        test_subject = StateArchiver(conf.get_lib_dir())
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

    def test_goal_state_history_init_should_purge_old_items(self):
        """
        GoalStateHistory.__init__ should _purge the MAX_ARCHIVED_STATES oldest files
        or directories.  The oldest timestamps are purged first.

        This test case creates a mixture of archive files and directories.
        It creates 5 more values than MAX_ARCHIVED_STATES to ensure that
        5 archives are cleaned up.  It asserts that the files and
        directories are properly deleted from the disk.
        """
        count = 6
        total = _MAX_ARCHIVED_STATES + count

        start = datetime.now(UTC)
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

        # NOTE: The purge method sorts the items by creation time, but the test files are created too fast and the
        # time resolution is too coarse, so instead we mock getctime to simply return the path of the file
        with patch("azurelinuxagent.common.utils.archive.os.path.getctime", side_effect=lambda path: path):
            GoalStateHistory(datetime.now(UTC), 'test')

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
            # SharedConfig.xml is used by other components (Azsec and Singularity/HPC Infiniband); verify that we do not delete it
            shared_config = os.path.join(self.tmp_dir, 'SharedConfig.xml')

            legacy_files = [
                'GoalState.2.xml',
                'VmSettings.2.json',
                'Prod.2.manifest.xml',
                'ExtensionsConfig.2.xml',
                'Microsoft.Azure.Extensions.CustomScript.1.xml',
                'HostingEnvironmentConfig.xml',
                'RemoteAccess.xml',
                'waagent_status.1.json'
            ]
            legacy_files = [os.path.join(self.tmp_dir, f) for f in legacy_files]

            self._write_file(shared_config)
            for f in legacy_files:
                self._write_file(f)

            StateArchiver.purge_legacy_goal_state_history()

            self.assertTrue(os.path.exists(shared_config), "{0} should not have been removed".format(shared_config))

            for f in legacy_files:
                self.assertFalse(os.path.exists(f), "Legacy file {0} was not removed".format(f))

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
