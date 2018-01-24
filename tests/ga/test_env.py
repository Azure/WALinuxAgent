# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#
import glob
import tempfile

import os
from mock import patch

from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.ga.env import MAXIMUM_CACHED_FILES, EnvHandler
from tests.tools import AgentTestCase


class TestEnv(AgentTestCase):
    @patch("azurelinuxagent.common.conf.get_lib_dir")
    def test_purge_disk_cache(self, mock_conf, *args):
        names = [
            ("Prod", "agentsManifest"),
            ("Test", "agentsManifest"),
            ("FauxExtension1", "manifest.xml"),
            ("FauxExtension2", "manifest.xml"),
            ("GoalState", "xml"),
            ("ExtensionsConfig", "xml")
        ]

        env = EnvHandler()

        tmp_dir = tempfile.mkdtemp()
        mock_conf.return_value = tmp_dir

        # write incarnations 1-100
        for t in names:
            self._create_files(tmp_dir,
                               t[0],
                               t[1],
                               2 * MAXIMUM_CACHED_FILES,
                               with_sleep=0.001)

        # update incarnation 1 with the latest timestamp
        for t in names:
            f = os.path.join(tmp_dir, '.'.join((t[0], '1', t[1])))
            fileutil.write_file(f, "faux content")

        # ensure the expected number of files are created
        for t in names:
            p = os.path.join(tmp_dir, '{0}.*.{1}'.format(*t))
            self.assertEqual(2 * MAXIMUM_CACHED_FILES, len(glob.glob(p)))

        env.purge_disk_cache()

        # ensure the expected number of files remain
        for t in names:
            p = os.path.join(tmp_dir, '{0}.*.{1}'.format(*t))
            incarnation1 = os.path.join(tmp_dir, '{0}.1.{1}'.format(t[0], t[1]))
            incarnation2 = os.path.join(tmp_dir, '{0}.2.{1}'.format(t[0], t[1]))
            self.assertEqual(MAXIMUM_CACHED_FILES, len(glob.glob(p)))
            self.assertTrue(os.path.exists(incarnation1))
            self.assertFalse(os.path.exists(incarnation2))

        # write incarnation 101
        for t in names:
            f = os.path.join(tmp_dir, '.'.join((t[0], '101', t[1])))
            fileutil.write_file(f, "faux content")

        # call to purge should be ignored, since interval has not elapsed
        env.purge_disk_cache()

        for t in names:
            p = os.path.join(tmp_dir, '{0}.*.{1}'.format(*t))
            incarnation1 = os.path.join(tmp_dir, '{0}.1.{1}'.format(t[0], t[1]))
            self.assertEqual(MAXIMUM_CACHED_FILES + 1, len(glob.glob(p)))
            self.assertTrue(os.path.exists(incarnation1))
