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

from __future__ import print_function

import copy
import glob
import json
import os
import platform
import random
import subprocess
import sys
import tempfile
import zipfile

from tests.protocol.mockwiredata import *
from tests.tools import *

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import *


class TestCurrentAgentName(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        return

    @patch("os.getcwd", return_value="/default/install/directory")
    def test_extract_name_finds_installed(self, mock_cwd):
        current_agent, current_version = set_current_agent()
        self.assertEqual(AGENT_LONG_VERSION, current_agent)
        self.assertEqual(AGENT_VERSION, str(current_version))
        return

    @patch("os.getcwd")
    def test_extract_name_finds_latest_agent(self, mock_cwd):
        path = os.path.join(conf.get_lib_dir(), "{0}-{1}".format(
            AGENT_NAME,
            "1.2.3"))
        mock_cwd.return_value = path
        agent = os.path.basename(path)
        version = AGENT_NAME_PATTERN.match(agent).group(1)
        current_agent, current_version = set_current_agent()
        self.assertEqual(agent, current_agent)
        self.assertEqual(version, str(current_version))
        return
