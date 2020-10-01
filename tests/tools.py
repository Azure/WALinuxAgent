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
import difflib
import os
import pprint
import re
import shutil
import stat
import sys
import tempfile
import time
import unittest
from functools import wraps
from threading import currentThread

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.event as event
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import range # pylint: disable=redefined-builtin
from azurelinuxagent.common.cgroupapi import SYSTEMD_RUN_PATH
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.version import PY_VERSION_MAJOR

try:
    from unittest.mock import Mock, patch, MagicMock, ANY, DEFAULT, call, PropertyMock # pylint: disable=unused-import,ungrouped-imports

    # Import mock module for Python2 and Python3
    from bin.waagent2 import Agent # pylint: disable=unused-import
except ImportError:
    from mock import Mock, patch, MagicMock, ANY, DEFAULT, call, PropertyMock

test_dir = os.path.dirname(os.path.abspath(__file__)) # pylint: disable=invalid-name
data_dir = os.path.join(test_dir, "data") # pylint: disable=invalid-name

debug = False # pylint: disable=invalid-name
if os.environ.get('DEBUG') == '1':
    debug = True # pylint: disable=invalid-name

# Enable verbose logger to stdout
if debug:
    logger.add_logger_appender(logger.AppenderType.STDOUT, 
                               logger.LogLevel.VERBOSE)

_MAX_LENGTH = 120

_MAX_LENGTH_SAFE_REPR = 80

# Mock sleep to reduce test execution time
_SLEEP = time.sleep


def mock_sleep(sec=0.01):
    """
    Mocks the time.sleep method to reduce unit test time
    :param sec: Time to replace the sleep call with, default = 0.01sec
    """
    _SLEEP(sec)


def safe_repr(obj, short=False):
    try:
        result = repr(obj)
    except Exception:
        result = object.__repr__(obj)
    if not short or len(result) < _MAX_LENGTH:
        return result
    return result[:_MAX_LENGTH_SAFE_REPR] + ' [truncated]...'


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


def running_under_travis():
    return 'TRAVIS' in os.environ and os.environ['TRAVIS'] == 'true'


def is_systemd_present():
    return os.path.exists(SYSTEMD_RUN_PATH)


def i_am_root():
    return os.geteuid() == 0


def is_python_version_26():
    return sys.version_info[0] == 2 and sys.version_info[1] == 6


class AgentTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls): # pylint: disable=too-many-branches
        # Setup newer unittest assertions missing in prior versions of Python

        if not hasattr(cls, "assertRegex"):
            cls.assertRegex = cls.assertRegexpMatches if hasattr(cls, "assertRegexpMatches") else cls.emulate_assertRegexpMatches
        if not hasattr(cls, "assertNotRegex"):
            cls.assertNotRegex = cls.assertNotRegexpMatches if hasattr(cls, "assertNotRegexpMatches") else cls.emulate_assertNotRegexpMatches # pylint: disable=no-member
        if not hasattr(cls, "assertIn"):
            cls.assertIn = cls.emulate_assertIn
        if not hasattr(cls, "assertNotIn"):
            cls.assertNotIn = cls.emulate_assertNotIn
        if not hasattr(cls, "assertGreater"):
            cls.assertGreater = cls.emulate_assertGreater
        if not hasattr(cls, "assertGreaterEqual"):
            cls.assertGreaterEqual = cls.emulate_assertGreaterEqual
        if not hasattr(cls, "assertLess"):
            cls.assertLess = cls.emulate_assertLess
        if not hasattr(cls, "assertLessEqual"):
            cls.assertLessEqual = cls.emulate_assertLessEqual
        if not hasattr(cls, "assertIsNone"):
            cls.assertIsNone = cls.emulate_assertIsNone
        if not hasattr(cls, "assertIsNotNone"):
            cls.assertIsNotNone = cls.emulate_assertIsNotNone
        if hasattr(cls, "assertRaisesRegexp"):
            cls.assertRaisesRegex = cls.assertRaisesRegexp
        if not hasattr(cls, "assertRaisesRegex"):
            cls.assertRaisesRegex = cls.emulate_raises_regex
        if not hasattr(cls, "assertListEqual"):
            cls.assertListEqual = cls.emulate_assertListEqual
        if not hasattr(cls, "assertIsInstance"):
            cls.assertIsInstance = cls.emulate_assertIsInstance
        if sys.version_info < (2, 7):
            # assertRaises does not implement a context manager in 2.6; override it with emulate_assertRaises but
            # keep a pointer to the original implementation to use when a context manager is not requested.
            cls.original_assertRaises = unittest.TestCase.assertRaises
            cls.assertRaises = cls.emulate_assertRaises
            cls.assertDictEqual = cls.emulate_assertDictEqual

    @classmethod
    def tearDownClass(cls):
        pass

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

    def emulate_assertIn(self, a, b, msg=None): # pylint: disable=invalid-name
        if a not in b:
            msg = msg if msg is not None else "{0} not found in {1}".format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertNotIn(self, a, b, msg=None): # pylint: disable=invalid-name
        if a in b:
            msg = msg if msg is not None else "{0} unexpectedly found in {1}".format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertGreater(self, a, b, msg=None): # pylint: disable=invalid-name
        if not a > b:
            msg = msg if msg is not None else '{0} not greater than {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertGreaterEqual(self, a, b, msg=None): # pylint: disable=invalid-name
        if not a >= b:
            msg = msg if msg is not None else '{0} not greater or equal to {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertLess(self, a, b, msg=None): # pylint: disable=invalid-name
        if not a < b:
            msg = msg if msg is not None else '{0} not less than {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertLessEqual(self, a, b, msg=None): # pylint: disable=invalid-name
        if not a <= b:
            msg = msg if msg is not None else '{0} not less or equal to {1}'.format(_safe_repr(a), _safe_repr(b))
            self.fail(msg)

    def emulate_assertIsNone(self, x, msg=None): # pylint: disable=invalid-name
        if x is not None:
            msg = msg if msg is not None else '{0} is not None'.format(_safe_repr(x))
            self.fail(msg)

    def emulate_assertIsNotNone(self, x, msg=None): # pylint: disable=invalid-name
        if x is None:
            msg = msg if msg is not None else '{0} is None'.format(_safe_repr(x))
            self.fail(msg)

    def emulate_assertRegexpMatches(self, text, regexp, msg=None): # pylint: disable=invalid-name
        if re.search(regexp, text) is not None:
            return
        msg = msg if msg is not None else "'{0}' does not match '{1}'.".format(text, regexp)
        self.fail(msg)

    def emulate_assertNotRegexpMatches(self, text, regexp, msg=None): # pylint: disable=invalid-name
        if re.search(regexp, text, flags=1) is None:
            return
        msg = msg if msg is not None else "'{0}' should not match '{1}'.".format(text, regexp)
        self.fail(msg)

    class _AssertRaisesContextManager(object):
        def __init__(self, expected_exception_type, test_case):
            self._expected_exception_type = expected_exception_type
            self._test_case = test_case

        def __enter__(self):
            return self

        @staticmethod
        def _get_type_name(type): # pylint: disable=redefined-builtin
            return type.__name__ if hasattr(type, "__name__") else str(type)

        def __exit__(self, exception_type, exception, *_):
            if exception_type is None:
                expected = AgentTestCase._AssertRaisesContextManager._get_type_name(self._expected_exception_type) # pylint: disable=protected-access
                self._test_case.fail("Did not raise an exception; expected '{0}'".format(expected))
            if not issubclass(exception_type, self._expected_exception_type):
                raised = AgentTestCase._AssertRaisesContextManager._get_type_name(exception_type) # pylint: disable=protected-access
                expected = AgentTestCase._AssertRaisesContextManager._get_type_name(self._expected_exception_type) # pylint: disable=protected-access
                self._test_case.fail("Raised '{0}', but expected '{1}'".format(raised, expected))

            self.exception = exception # pylint: disable=attribute-defined-outside-init
            return True

    def emulate_assertRaises(self, exception_type, function=None, *args, **kwargs): # pylint: disable=invalid-name,keyword-arg-before-vararg
        # return a context manager only when function is not provided; otherwise use the original assertRaises
        if function is None:
            return AgentTestCase._AssertRaisesContextManager(exception_type, self)

        self.original_assertRaises(exception_type, function, *args, **kwargs)

        return None

    def emulate_raises_regex(self, exception_type, regex, function, *args, **kwargs):
        try:
            function(*args, **kwargs)
        except Exception as e: # pylint: disable=invalid-name
            if re.search(regex, str(e), flags=1) is not None: # pylint: disable=no-else-return
                return
            else:
                self.fail("Expected exception {0} matching {1}.  Actual: {2}".format(
                    exception_type, regex, str(e)))
        self.fail("No exception was thrown.  Expected exception {0} matching {1}".format(exception_type, regex))

    def emulate_assertDictEqual(self, first, second, msg=None): # pylint: disable=invalid-name
        def fail(message):
            self.fail(self._formatMessage(msg, message))

        for k in first.keys():
            if k not in second:
                fail("'{0}' is missing from second".format(k))
            if first[k] != second[k]:
                fail("'{0}' != '{1}' (key: {2})".format(first[k], second[k], k))

        for k in second.keys():
            if k not in first:
                fail("'{0}' is missing from first".format(k))

    def emulate_assertListEqual(self, seq1, seq2, msg=None, seq_type=None): # pylint: disable=too-many-locals,too-many-branches,invalid-name
        """An equality assertion for ordered sequences (like lists and tuples).

        For the purposes of this function, a valid ordered sequence type is one
        which can be indexed, has a length, and has an equality operator.

        Args:
            seq1: The first sequence to compare.
            seq2: The second sequence to compare.
            seq_type: The expected datatype of the sequences, or None if no
                    datatype should be enforced.
            msg: Optional message to use on failure instead of a list of
                    differences.
        """
        if seq_type is not None:
            seq_type_name = seq_type.__name__
            if not isinstance(seq1, seq_type):
                raise self.failureException('First sequence is not a %s: %s'
                                        % (seq_type_name, safe_repr(seq1)))
            if not isinstance(seq2, seq_type):
                raise self.failureException('Second sequence is not a %s: %s'
                                        % (seq_type_name, safe_repr(seq2)))
        else:
            seq_type_name = "sequence"

        differing = None
        try:
            len1 = len(seq1)
        except (TypeError, NotImplementedError):
            differing = 'First %s has no length.    Non-sequence?' % (
                    seq_type_name)

        if differing is None:
            try:
                len2 = len(seq2)
            except (TypeError, NotImplementedError):
                differing = 'Second %s has no length.    Non-sequence?' % (
                        seq_type_name)

        if differing is None:
            if seq1 == seq2:
                return

            seq1_repr = safe_repr(seq1)
            seq2_repr = safe_repr(seq2)
            if len(seq1_repr) > 30:
                seq1_repr = seq1_repr[:30] + '...'
            if len(seq2_repr) > 30:
                seq2_repr = seq2_repr[:30] + '...'
            elements = (seq_type_name.capitalize(), seq1_repr, seq2_repr)
            differing = '%ss differ: %s != %s\n' % elements

            for i in range(min(len1, len2)):
                try:
                    item1 = seq1[i]
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('\nUnable to index element %d of first %s\n' %
                                 (i, seq_type_name))
                    break

                try:
                    item2 = seq2[i]
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('\nUnable to index element %d of second %s\n' %
                                 (i, seq_type_name))
                    break

                if item1 != item2:
                    differing += ('\nFirst differing element %d:\n%s\n%s\n' %
                                 (i, safe_repr(item1), safe_repr(item2)))
                    break
            else:
                if (len1 == len2 and seq_type is None and
                    type(seq1) != type(seq2)): # pylint: disable=unidiomatic-typecheck
                    # The sequences are the same, but have differing types.
                    return

            if len1 > len2:
                differing += ('\nFirst %s contains %d additional '
                             'elements.\n' % (seq_type_name, len1 - len2))
                try:
                    differing += ('First extra element %d:\n%s\n' %
                                  (len2, safe_repr(seq1[len2])))
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('Unable to index element %d '
                                  'of first %s\n' % (len2, seq_type_name))
            elif len1 < len2:
                differing += ('\nSecond %s contains %d additional '
                             'elements.\n' % (seq_type_name, len2 - len1))
                try:
                    differing += ('First extra element %d:\n%s\n' %
                                  (len1, safe_repr(seq2[len1])))
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('Unable to index element %d '
                                  'of second %s\n' % (len1, seq_type_name))
        standardMsg = differing # pylint: disable=invalid-name
        diffMsg = '\n' + '\n'.join( # pylint: disable=invalid-name
            difflib.ndiff(pprint.pformat(seq1).splitlines(),
                          pprint.pformat(seq2).splitlines()))
        standardMsg = self._truncateMessage(standardMsg, diffMsg) # pylint: disable=invalid-name
        msg = self._formatMessage(msg, standardMsg)
        self.fail(msg)

    def emulate_assertIsInstance(self, obj, object_type, msg=None): # pylint: disable=invalid-name
        if not isinstance(obj, object_type):
            msg = msg if msg is not None else '{0} is not an instance of {1}'.format(_safe_repr(obj),
                                                                                     _safe_repr(object_type))
            self.fail(msg)

    @staticmethod
    def _create_files(tmp_dir, prefix, suffix, count, with_sleep=0):
        for i in range(count):
            f = os.path.join(tmp_dir, '.'.join((prefix, str(i), suffix))) # pylint: disable=invalid-name
            fileutil.write_file(f, "faux content")
            time.sleep(with_sleep)

    def create_script(self, file_name, contents, file_path=None):
        """
        Creates an executable script with the given contents.
        If file_name ends with ".py", it creates a Python3 script, otherwise it creates a bash script
        :param file_name: The name of the file to create the script with
        :param contents: Contents of the script file
        :param file_path: The path of the file where to create it in (we use /tmp/ by default)
        :return:
        """
        if not file_path:
            file_path = os.path.join(self.tmp_dir, file_name)

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.mkdir(directory)

        with open(file_path, "w") as script:
            if file_name.endswith(".py"):
                script.write("#!/usr/bin/env python3\n")
            else:
                script.write("#!/usr/bin/env bash\n")
            script.write(contents)

        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        return file_name


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


supported_distro = [ # pylint: disable=invalid-name
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


def clear_singleton_instances(cls):
    # Adding this lock to avoid any race conditions
    with cls._lock: # pylint: disable=protected-access
        obj_name = "%s__%s" % (cls.__name__, currentThread().getName())  # Object Name = className__threadName
        if obj_name in cls._instances: # pylint: disable=protected-access
            del cls._instances[obj_name] # pylint: disable=protected-access
