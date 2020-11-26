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
# test_future.py - exercise the new code added to future.py
# to re-check if the distro is reported as debian
# 
# Problems when testing on github:
# - assertListEqual doesn't exist in python 2.6
#   fix: use AgentTestCase (assertListEqual is 
#   emulated in it)
# - platform.linux_distribution doesn't exist in python > 3.7
#   fix: 
#     in future.py, if platform.linux_distribution is not present, distro is
#     used automatically. future.py does a lot of work to maintain compatibility
#     across python versions - need to understand it and emulate it here.
#     Could be argued that we're not interested in distro - it identifies
#     devuan correctly.

import sys
import unittest
# (fix pylint unused-import)
# from mock import Mock, patch
from mock import patch
from tests.tools import AgentTestCase, skip_if_predicate_true

from azurelinuxagent.common.future import get_linux_distribution

def is_pyver_gt_37():
    return sys.version_info[0] == 3 and sys.version_info[1] > 7

# class TestFuture(unittest.TestCase):
# (above won't work in python 2.6 - no assertListEqual
# - emulated in AgentTestCase class)
class TestFuture(AgentTestCase):

# platform.linux_distribution removed after 3.7
    @skip_if_predicate_true(is_pyver_gt_37, \
    'platform.linux_distribution was removed in python 3.8')
    @patch('platform.linux_distribution')
    @patch('azurelinuxagent.common.future.DebianRecheck')
    def test_get_linux_distribution_it_should_return_debian(self, mock_recheck, mock_linuxdist):
        debian_list = ['debian', '9.0', '', 'debian']
#       print("mock_recheck = ", mock_recheck)
        mock_linuxdist.return_value = ['debian', '9.0', 'debian']
        mock_recheck.return_value.get_id.return_value = 'debian'
        mock_recheck.return_value.get_release.return_value = '9.0'
        osinfo = get_linux_distribution(0, ['alpine', 'devuan'])
        self.assertListEqual(debian_list, osinfo)

    @skip_if_predicate_true(is_pyver_gt_37, \
    'platform.linux_distribution was removed in python 3.8')
    @patch('platform.linux_distribution')
    def test_get_linux_distribution_it_should_return_devuan(self, mock_linuxdist):
        devuan_list = ['devuan', '3.0', 'devuan', 'devuan']
        mock_linuxdist.return_value = ['devuan', '3.0', 'devuan']
        osinfo = get_linux_distribution(0, ['alpine', 'devuan'])
        self.assertListEqual(devuan_list, osinfo)

if __name__ == '__main__':
#   print("(running from command line)")
    unittest.main()
