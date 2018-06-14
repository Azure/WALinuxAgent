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

"""
Define util functions for unit test
"""

import os
import re
import shutil
import tempfile
import unittest
from functools import wraps

import time

import azurelinuxagent.common.event as event
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils import fileutil

from azurelinuxagent.common.version import PY_VERSION_MAJOR

# Import mock module for Python2 and Python3
try:
    from unittest.mock import Mock, patch, MagicMock, ANY, DEFAULT, call
except ImportError:
    from mock import Mock, patch, MagicMock, ANY, DEFAULT, call

test_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(test_dir, "data")

debug = False
if os.environ.get('DEBUG') == '1':
    debug = True

# Enable verbose logger to stdout
if debug:
    logger.add_logger_appender(logger.AppenderType.STDOUT, 
                               logger.LogLevel.VERBOSE)


def _do_nothing():
    pass


_MAX_LENGTH = 120


def skip_if_predicate_false(predicate, message):
    if not predicate():
        if hasattr(unittest, "skip"):
            return unittest.skip(message)
        return lambda func: None
    return lambda func: func


def skip_if_predicate_true(predicate, message):
    if predicate():
        if hasattr(unittest, "skip"):
            return unittest.skip(message)
        return lambda func: None
    return lambda func: func


def _safe_repr(obj, short=False):
    """
    Copied from Python 3.x
    """
    try:
        result = repr(obj)
    except Exception:
        result = object.__repr__(obj)
    if not short or len(result) < _MAX_LENGTH:
        return result
    return result[:_MAX_LENGTH] + ' [truncated]...'


class AgentTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup newer unittest assertions missing in prior versions of Python

        if not hasattr(cls, "assertRegex"):
            cls.assertRegex = cls.assertRegexpMatches if hasattr(cls, "assertRegexpMatches") else _do_nothing
        if not hasattr(cls, "assertNotRegex"):
            cls.assertNotRegex = cls.assertNotRegexpMatches if hasattr(cls, "assertNotRegexpMatches") else _do_nothing
        if not hasattr(cls, "assertIn"):
            cls.assertIn = cls.emulate_assertIn
        if not hasattr(cls, "assertNotIn"):
            cls.assertNotIn = cls.emulate_assertNotIn
        if not hasattr(cls, "assertGreater"):
            cls.assertGreater = cls.emulate_assertGreater
        if not hasattr(cls, "assertLess"):
            cls.assertLess = cls.emulate_assertLess
        if not hasattr(cls, "assertIsNone"):
            cls.assertIsNone = cls.emulate_assertIsNone
        if not hasattr(cls, "assertIsNotNone"):
            cls.assertIsNone = cls.emulate_assertIsNotNone

    def setUp(self):
        prefix = "{0}_".format(self.__class__.__name__)

        self.tmp_dir = tempfile.mkdtemp(prefix=prefix)
        self.test_file = 'test_file'

        conf.get_autoupdate_enabled = Mock(return_value=True)
        conf.get_lib_dir = Mock(return_value=self.tmp_dir)

        ext_log_dir = os.path.join(self.tmp_dir, "azure")
        conf.get_ext_log_dir = Mock(return_value=ext_log_dir)

        conf.get_agent_pid_file_path = Mock(return_value=os.path.join(self.tmp_dir, "waagent.pid"))

        event.init_event_status(self.tmp_dir)
        event.init_event_logger(self.tmp_dir)

    def tearDown(self):
        if not debug and self.tmp_dir is not None:
            shutil.rmtree(self.tmp_dir)

    def emulate_assertIn(self, a, b, msg=None):
        if a not in b:
            msg = msg if msg is not None else "{0} not found in {1}".format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertNotIn(self, a, b, msg=None):
        if a in b:
            msg = msg if msg is not None else "{0} unexpectedly found in {1}".format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertGreater(self, a, b, msg=None):
        if not a > b:
            msg = msg if msg is not None else '{0} not greater than {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertLess(self, a, b, msg=None):
        if not a < b:
            msg = msg if msg is not None else '{0} not less than {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertIsNone(self, x, msg=None):
        if x is not None:
            msg = msg if msg is not None else '{0} is not None'.format(_safe_repr(x))
            self.fail(msg)

    def emulate_assertIsNotNone(self, x, msg=None):
        if x is None:
            msg = msg if msg is not None else '{0} is None'.format(_safe_repr(x))
            self.fail(msg)

    @staticmethod
    def _create_files(tmp_dir, prefix, suffix, count, with_sleep=0):
        for i in range(count):
            f = os.path.join(tmp_dir, '.'.join((prefix, str(i), suffix)))
            fileutil.write_file(f, "faux content")
            time.sleep(with_sleep)


def load_data(name):
    """Load test data"""
    path = os.path.join(data_dir, name)
    with open(path, "r") as data_file:
        return data_file.read()


def load_bin_data(name):
    """Load test bin data"""
    path = os.path.join(data_dir, name)
    with open(path, "rb") as data_file:
        return data_file.read()


supported_distro = [
    ["ubuntu", "12.04", ""],
    ["ubuntu", "14.04", ""],
    ["ubuntu", "14.10", ""],
    ["ubuntu", "15.10", ""],
    ["ubuntu", "15.10", "Snappy Ubuntu Core"],

    ["coreos", "", ""],

    ["suse", "12", "SUSE Linux Enterprise Server"],
    ["suse", "13.2", "openSUSE"],
    ["suse", "11", "SUSE Linux Enterprise Server"],
    ["suse", "13.1", "openSUSE"],

    ["debian", "6.0", ""],

    ["redhat", "6.5", ""],
    ["redhat", "7.0", ""],

]


def open_patch():
    open_name = '__builtin__.open'
    if PY_VERSION_MAJOR == 3:
        open_name = 'builtins.open'
    return open_name


def distros(distro_name=".*", distro_version=".*", distro_full_name=".*"):
    """Run test on multiple distros"""
    def decorator(test_method):
        @wraps(test_method)
        def wrapper(self, *args, **kwargs):
            for distro in supported_distro:
                if re.match(distro_name, distro[0]) and \
                   re.match(distro_version, distro[1]) and \
                   re.match(distro_full_name, distro[2]):
                    if debug:
                        logger.info("Run {0} on {1}", test_method.__name__, 
                                    distro)
                    new_args = []
                    new_args.extend(args)
                    new_args.extend(distro)
                    test_method(self, *new_args, **kwargs)
                    # Call tearDown and setUp to create separated environment
                    # for distro testing
                    self.tearDown()
                    self.setUp()
        return wrapper
    return decorator


