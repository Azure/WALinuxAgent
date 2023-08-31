# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

from __future__ import print_function

import contextlib
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile

from datetime import datetime, timedelta
from threading import current_thread
from azurelinuxagent.ga.guestagent import GuestAgent, GuestAgentError, \
    AGENT_ERROR_FILE, GAUpdateReportState
from tests.common.osutil.test_default import TestOSUtil
import azurelinuxagent.common.osutil.default as osutil

_ORIGINAL_POPEN = subprocess.Popen

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY, WALAEventOperation
from azurelinuxagent.common.exception import HttpError, \
    ExitException, AgentMemoryExceededException
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.ga.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.hostplugin import HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import VMAgentFamily, \
    ExtHandlerPackage, ExtHandlerPackageList, Extension, VMStatus, ExtHandlerStatus, ExtensionStatus, \
    VMAgentUpdateStatuses
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.utils import fileutil, textutil, timeutil
from azurelinuxagent.common.utils.archive import ARCHIVE_DIRECTORY_NAME, AGENT_STATUS_FILE
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.networkutil import FirewallCmdDirectCommands, AddFirewallRules
from azurelinuxagent.common.version import AGENT_PKG_GLOB, AGENT_DIR_GLOB, AGENT_NAME, AGENT_DIR_PATTERN, \
    AGENT_VERSION, CURRENT_AGENT, CURRENT_VERSION, set_daemon_version, __DAEMON_VERSION_ENV_VARIABLE as DAEMON_VERSION_ENV_VARIABLE
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler, ExtHandlerInstance, HandlerEnvironment, ExtensionStatusValue
from azurelinuxagent.ga.update import  \
    get_update_handler, ORPHAN_POLL_INTERVAL, AGENT_PARTITION_FILE, ORPHAN_WAIT_INTERVAL, \
    CHILD_LAUNCH_RESTART_MAX, CHILD_HEALTH_INTERVAL, GOAL_STATE_PERIOD_EXTENSIONS_DISABLED, UpdateHandler, \
    READONLY_FILE_GLOBS, ExtensionsSummary
from tests.lib.mock_update_handler import mock_update_handler
from tests.lib.mock_wire_protocol import mock_wire_protocol, MockHttpResponse
from tests.lib.wire_protocol_data import DATA_FILE, DATA_FILE_MULTIPLE_EXT, DATA_FILE_VM_SETTINGS
from tests.lib.tools import AgentTestCase, AgentTestCaseWithGetVmSizeMock, data_dir, DEFAULT, patch, load_bin_data, Mock, MagicMock, \
    clear_singleton_instances, is_python_version_26_or_34, skip_if_predicate_true
from tests.lib import wire_protocol_data
from tests.lib.http_request_predicates import HttpRequestPredicates


NO_ERROR = {
    "last_failure": 0.0,
    "failure_count": 0,
    "was_fatal": False,
    "reason": ''
}

FATAL_ERROR = {
    "last_failure": 42.42,
    "failure_count": 2,
    "was_fatal": True,
    "reason": "Test failure"
}

WITH_ERROR = {
    "last_failure": 42.42,
    "failure_count": 2,
    "was_fatal": False,
    "reason": "Test failure"
}

EMPTY_MANIFEST = {
    "name": "WALinuxAgent",
    "version": 1.0,
    "handlerManifest": {
        "installCommand": "",
        "uninstallCommand": "",
        "updateCommand": "",
        "enableCommand": "",
        "disableCommand": "",
        "rebootAfterInstall": False,
        "reportHeartbeat": False
    }
}


def faux_logger():
    print("STDOUT message")
    print("STDERR message", file=sys.stderr)
    return DEFAULT


@contextlib.contextmanager
def _get_update_handler(iterations=1, test_data=None, protocol=None, autoupdate_enabled=True):
    """
    This function returns a mocked version of the UpdateHandler object to be used for testing. It will only run the
    main loop [iterations] no of times.
    """

    test_data = DATA_FILE if test_data is None else test_data

    with patch.object(HostPluginProtocol, "is_default_channel", False):
        if protocol is None:
            with mock_wire_protocol(test_data) as mock_protocol:
                with mock_update_handler(mock_protocol, iterations=iterations, autoupdate_enabled=autoupdate_enabled) as update_handler:
                    yield update_handler, mock_protocol
        else:
            with mock_update_handler(protocol, iterations=iterations, autoupdate_enabled=autoupdate_enabled) as update_handler:
                yield update_handler, protocol


class UpdateTestCase(AgentTestCaseWithGetVmSizeMock):
    _test_suite_tmp_dir = None
    _agent_zip_dir = None

    @classmethod
    def setUpClass(cls):
        super(UpdateTestCase, cls).setUpClass()
        # copy data_dir/ga/WALinuxAgent-0.0.0.0.zip to _test_suite_tmp_dir/waagent-zip/WALinuxAgent-<AGENT_VERSION>.zip
        sample_agent_zip = "WALinuxAgent-0.0.0.0.zip"
        test_agent_zip = sample_agent_zip.replace("0.0.0.0", AGENT_VERSION)
        UpdateTestCase._test_suite_tmp_dir = tempfile.mkdtemp()
        UpdateTestCase._agent_zip_dir = os.path.join(UpdateTestCase._test_suite_tmp_dir, "waagent-zip")
        os.mkdir(UpdateTestCase._agent_zip_dir)
        source = os.path.join(data_dir, "ga", sample_agent_zip)
        target = os.path.join(UpdateTestCase._agent_zip_dir, test_agent_zip)
        shutil.copyfile(source, target)
        # The update_handler inherently calls agent update handler, which in turn calls daemon version. So now daemon version logic has fallback if env variable is not set.
        # The fallback calls popen which is not mocked. So we set the env variable to avoid the fallback.
        # This will not change any of the test validations. At the ene of all update test validations, we reset the env variable.
        set_daemon_version("1.2.3.4")

    @classmethod
    def tearDownClass(cls):
        super(UpdateTestCase, cls).tearDownClass()
        shutil.rmtree(UpdateTestCase._test_suite_tmp_dir)
        os.environ.pop(DAEMON_VERSION_ENV_VARIABLE)

    @staticmethod
    def _get_agent_pkgs(in_dir=None):
        if in_dir is None:
            in_dir = UpdateTestCase._agent_zip_dir
        path = os.path.join(in_dir, AGENT_PKG_GLOB)
        return glob.glob(path)

    @staticmethod
    def _get_agents(in_dir=None):
        if in_dir is None:
            in_dir = UpdateTestCase._agent_zip_dir
        path = os.path.join(in_dir, AGENT_DIR_GLOB)
        return [a for a in glob.glob(path) if os.path.isdir(a)]

    @staticmethod
    def _get_agent_file_path():
        return UpdateTestCase._get_agent_pkgs()[0]

    @staticmethod
    def _get_agent_file_name():
        return os.path.basename(UpdateTestCase._get_agent_file_path())

    @staticmethod
    def _get_agent_path():
        return fileutil.trim_ext(UpdateTestCase._get_agent_file_path(), "zip")

    @staticmethod
    def _get_agent_name():
        return os.path.basename(UpdateTestCase._get_agent_path())

    @staticmethod
    def _get_agent_version():
        return FlexibleVersion(UpdateTestCase._get_agent_name().split("-")[1])

    @staticmethod
    def _add_write_permission_to_goal_state_files():
        # UpdateHandler.run() marks some of the files from the goal state as read-only. Those files are overwritten when
        # a new goal state is fetched. This is not a problem for the agent, since it  runs as root, but tests need
        # to make those files writtable before fetching a new goal state. Note that UpdateHandler.run() fetches a new
        # goal state, so tests that make multiple calls to that method need to call this function in-between calls.
        for gb in READONLY_FILE_GLOBS:
            for path in glob.iglob(os.path.join(conf.get_lib_dir(), gb)):
                fileutil.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def agent_bin(self, version, suffix):
        return "bin/{0}-{1}{2}.egg".format(AGENT_NAME, version, suffix)

    def rename_agent_bin(self, path, dst_v):
        src_bin = glob.glob(os.path.join(path, self.agent_bin("*.*.*.*", '*')))[0]
        dst_bin = os.path.join(path, self.agent_bin(dst_v, ''))
        shutil.move(src_bin, dst_bin)

    def agents(self):
        return [GuestAgent.from_installed_agent(path) for path in self.agent_dirs()]

    def agent_count(self):
        return len(self.agent_dirs())

    def agent_dirs(self):
        return self._get_agents(in_dir=self.tmp_dir)

    def agent_dir(self, version):
        return os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, version))

    def agent_paths(self):
        paths = glob.glob(os.path.join(self.tmp_dir, "*"))
        paths.sort()
        return paths

    def agent_pkgs(self):
        return self._get_agent_pkgs(in_dir=self.tmp_dir)

    def agent_versions(self):
        v = [FlexibleVersion(AGENT_DIR_PATTERN.match(a).group(1)) for a in self.agent_dirs()]
        v.sort(reverse=True)
        return v

    @contextlib.contextmanager
    def get_error_file(self, error_data=None):
        if error_data is None:
            error_data = NO_ERROR
        with tempfile.NamedTemporaryFile(mode="w") as fp:
            json.dump(error_data if error_data is not None else NO_ERROR, fp)
            fp.seek(0)
            yield fp

    def create_error(self, error_data=None):
        if error_data is None:
            error_data = NO_ERROR
        with self.get_error_file(error_data) as path:
            err = GuestAgentError(path.name)
            err.load()
            return err

    def copy_agents(self, *agents):
        if len(agents) <= 0:
            agents = self._get_agent_pkgs()
        for agent in agents:
            shutil.copy(agent, self.tmp_dir)
        return

    def expand_agents(self):
        for agent in self.agent_pkgs():
            path = os.path.join(self.tmp_dir, fileutil.trim_ext(agent, "zip"))
            zipfile.ZipFile(agent).extractall(path)

    def prepare_agent(self, version):
        """
        Create a download for the current agent version, copied from test data
        """
        self.copy_agents(self._get_agent_pkgs()[0])
        self.expand_agents()

        versions = self.agent_versions()
        src_v = FlexibleVersion(str(versions[0]))

        from_path = self.agent_dir(src_v)
        dst_v = FlexibleVersion(str(version))
        to_path = self.agent_dir(dst_v)

        if from_path != to_path:
            shutil.move(from_path + ".zip", to_path + ".zip")
            shutil.move(from_path, to_path)
            self.rename_agent_bin(to_path, dst_v)
        return

    def prepare_agents(self,
                       count=20,
                       is_available=True):

        # Ensure the test data is copied over
        agent_count = self.agent_count()
        if agent_count <= 0:
            self.copy_agents(self._get_agent_pkgs()[0])
            self.expand_agents()
            count -= 1

        # Determine the most recent agent version
        versions = self.agent_versions()
        src_v = FlexibleVersion(str(versions[0]))

        # Create agent packages and directories
        return self.replicate_agents(
            src_v=src_v,
            count=count - agent_count,
            is_available=is_available)

    def remove_agents(self):
        for agent in self.agent_paths():
            try:
                if os.path.isfile(agent):
                    os.remove(agent)
                else:
                    shutil.rmtree(agent)
            except:  # pylint: disable=bare-except
                pass
        return

    def replicate_agents(self,
                         count=5,
                         src_v=AGENT_VERSION,
                         is_available=True,
                         increment=1):
        from_path = self.agent_dir(src_v)
        dst_v = FlexibleVersion(str(src_v))
        for i in range(0, count):  # pylint: disable=unused-variable
            dst_v += increment
            to_path = self.agent_dir(dst_v)
            shutil.copyfile(from_path + ".zip", to_path + ".zip")
            shutil.copytree(from_path, to_path)
            self.rename_agent_bin(to_path, dst_v)
            if not is_available:
                GuestAgent.from_installed_agent(to_path).mark_failure(is_fatal=True)
        return dst_v


class TestUpdate(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.event_patch = patch('azurelinuxagent.common.event.add_event')
        self.update_handler = get_update_handler()
        protocol = Mock()
        self.update_handler.protocol_util = Mock()
        self.update_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        self.update_handler._goal_state = Mock()
        self.update_handler._goal_state.extensions_goal_state = Mock()
        self.update_handler._goal_state.extensions_goal_state.source = "Fabric"
        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not reuse
        # a previous state
        clear_singleton_instances(ProtocolUtil)

    def test_creation(self):
        self.assertEqual(0, len(self.update_handler.agents))

        self.assertEqual(None, self.update_handler.child_agent)
        self.assertEqual(None, self.update_handler.child_launch_time)
        self.assertEqual(0, self.update_handler.child_launch_attempts)
        self.assertEqual(None, self.update_handler.child_process)

        self.assertEqual(None, self.update_handler.signal_handler)

    def test_emit_restart_event_emits_event_if_not_clean_start(self):
        try:
            mock_event = self.event_patch.start()
            self.update_handler._set_sentinel()
            self.update_handler._emit_restart_event()
            self.assertEqual(1, mock_event.call_count)
        except Exception as e:  # pylint: disable=unused-variable
            pass
        self.event_patch.stop()

    def _create_protocol(self, count=20, versions=None):
        latest_version = self.prepare_agents(count=count)
        if versions is None or len(versions) <= 0:
            versions = [latest_version]
        return ProtocolMock(versions=versions)

    def _test_ensure_no_orphans(self, invocations=3, interval=ORPHAN_WAIT_INTERVAL, pid_count=0):
        with patch.object(self.update_handler, 'osutil') as mock_util:
            # Note:
            # - Python only allows mutations of objects to which a function has
            #   a reference. Incrementing an integer directly changes the
            #   reference. Incrementing an item of a list changes an item to
            #   which the code has a reference.
            #   See http://stackoverflow.com/questions/26408941/python-nested-functions-and-variable-scope
            iterations = [0]

            def iterator(*args, **kwargs):  # pylint: disable=unused-argument
                iterations[0] += 1
                return iterations[0] < invocations

            mock_util.check_pid_alive = Mock(side_effect=iterator)

            pid_files = self.update_handler._get_pid_files()
            self.assertEqual(pid_count, len(pid_files))

            with patch('os.getpid', return_value=42):
                with patch('time.sleep', return_value=None) as mock_sleep:  # pylint: disable=redefined-outer-name
                    self.update_handler._ensure_no_orphans(orphan_wait_interval=interval)
                    for pid_file in pid_files:
                        self.assertFalse(os.path.exists(pid_file))
                    return mock_util.check_pid_alive.call_count, mock_sleep.call_count

    def test_ensure_no_orphans(self):
        fileutil.write_file(os.path.join(self.tmp_dir, "0_waagent.pid"), ustr(41))
        calls, sleeps = self._test_ensure_no_orphans(invocations=3, pid_count=1)
        self.assertEqual(3, calls)
        self.assertEqual(2, sleeps)

    def test_ensure_no_orphans_skips_if_no_orphans(self):
        calls, sleeps = self._test_ensure_no_orphans(invocations=3)
        self.assertEqual(0, calls)
        self.assertEqual(0, sleeps)

    def test_ensure_no_orphans_ignores_exceptions(self):
        with patch('azurelinuxagent.common.utils.fileutil.read_file', side_effect=Exception):
            calls, sleeps = self._test_ensure_no_orphans(invocations=3)
            self.assertEqual(0, calls)
            self.assertEqual(0, sleeps)

    def test_ensure_no_orphans_kills_after_interval(self):
        fileutil.write_file(os.path.join(self.tmp_dir, "0_waagent.pid"), ustr(41))
        with patch('os.kill') as mock_kill:
            calls, sleeps = self._test_ensure_no_orphans(
                invocations=4,
                interval=3 * ORPHAN_POLL_INTERVAL,
                pid_count=1)
            self.assertEqual(3, calls)
            self.assertEqual(2, sleeps)
            self.assertEqual(1, mock_kill.call_count)

    @patch('azurelinuxagent.ga.update.datetime')
    def test_ensure_partition_assigned(self, mock_time):
        path = os.path.join(conf.get_lib_dir(), AGENT_PARTITION_FILE)
        mock_time.utcnow = Mock()

        self.assertFalse(os.path.exists(path))

        for n in range(0, 99):
            mock_time.utcnow.return_value = Mock(microsecond=n * 10000)

            self.update_handler._ensure_partition_assigned()

            self.assertTrue(os.path.exists(path))
            s = fileutil.read_file(path)
            self.assertEqual(n, int(s))
            os.remove(path)

    def test_ensure_readonly_sets_readonly(self):
        test_files = [
            os.path.join(conf.get_lib_dir(), "faux_certificate.crt"),
            os.path.join(conf.get_lib_dir(), "faux_certificate.p7m"),
            os.path.join(conf.get_lib_dir(), "faux_certificate.pem"),
            os.path.join(conf.get_lib_dir(), "faux_certificate.prv"),
            os.path.join(conf.get_lib_dir(), "ovf-env.xml")
        ]
        for path in test_files:
            fileutil.write_file(path, "Faux content")
            os.chmod(path,
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        self.update_handler._ensure_readonly_files()

        for path in test_files:
            mode = os.stat(path).st_mode
            mode &= (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            self.assertEqual(0, mode ^ stat.S_IRUSR)

    def test_ensure_readonly_leaves_unmodified(self):
        test_files = [
            os.path.join(conf.get_lib_dir(), "faux.xml"),
            os.path.join(conf.get_lib_dir(), "faux.json"),
            os.path.join(conf.get_lib_dir(), "faux.txt"),
            os.path.join(conf.get_lib_dir(), "faux")
        ]
        for path in test_files:
            fileutil.write_file(path, "Faux content")
            os.chmod(path,
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        self.update_handler._ensure_readonly_files()

        for path in test_files:
            mode = os.stat(path).st_mode
            mode &= (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            self.assertEqual(
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                mode)

    def _test_evaluate_agent_health(self, child_agent_index=0):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertTrue(latest_agent.is_available)
        self.assertFalse(latest_agent.is_blacklisted)
        self.assertTrue(len(self.update_handler.agents) > 1)

        child_agent = self.update_handler.agents[child_agent_index]
        self.assertTrue(child_agent.is_available)
        self.assertFalse(child_agent.is_blacklisted)
        self.update_handler.child_agent = child_agent

        self.update_handler._evaluate_agent_health(latest_agent)

    def test_evaluate_agent_health_ignores_installed_agent(self):
        self.update_handler._evaluate_agent_health(None)

    def test_evaluate_agent_health_raises_exception_for_restarting_agent(self):
        self.update_handler.child_launch_time = time.time() - (4 * 60)
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 1
        self.assertRaises(Exception, self._test_evaluate_agent_health)

    def test_evaluate_agent_health_will_not_raise_exception_for_long_restarts(self):
        self.update_handler.child_launch_time = time.time() - 24 * 60
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX
        self._test_evaluate_agent_health()

    def test_evaluate_agent_health_will_not_raise_exception_too_few_restarts(self):
        self.update_handler.child_launch_time = time.time()
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 2
        self._test_evaluate_agent_health()

    def test_evaluate_agent_health_resets_with_new_agent(self):
        self.update_handler.child_launch_time = time.time() - (4 * 60)
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 1
        self._test_evaluate_agent_health(child_agent_index=1)
        self.assertEqual(1, self.update_handler.child_launch_attempts)

    def test_filter_blacklisted_agents(self):
        self.prepare_agents()

        self.update_handler._set_and_sort_agents([GuestAgent.from_installed_agent(path) for path in self.agent_dirs()])
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))

        kept_agents = self.update_handler.agents[::2]
        blacklisted_agents = self.update_handler.agents[1::2]
        for agent in blacklisted_agents:
            agent.mark_failure(is_fatal=True)
        self.update_handler._filter_blacklisted_agents()
        self.assertEqual(kept_agents, self.update_handler.agents)

    def test_find_agents(self):
        self.prepare_agents()

        self.assertTrue(0 <= len(self.update_handler.agents))
        self.update_handler._find_agents()
        self.assertEqual(len(self._get_agents(self.tmp_dir)), len(self.update_handler.agents))

    def test_find_agents_does_reload(self):
        self.prepare_agents()

        self.update_handler._find_agents()
        agents = self.update_handler.agents

        self.update_handler._find_agents()
        self.assertNotEqual(agents, self.update_handler.agents)

    def test_find_agents_sorts(self):
        self.prepare_agents()
        self.update_handler._find_agents()

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version

    def test_get_latest_agent(self):
        latest_version = self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertEqual(len(self._get_agents(self.tmp_dir)), len(self.update_handler.agents))
        self.assertEqual(latest_version, latest_agent.version)

    def test_get_latest_agent_excluded(self):
        self.prepare_agent(AGENT_VERSION)
        self.assertEqual(None, self.update_handler.get_latest_agent_greater_than_daemon())

    def test_get_latest_agent_no_updates(self):
        self.assertEqual(None, self.update_handler.get_latest_agent_greater_than_daemon())

    def test_get_latest_agent_skip_updates(self):
        conf.get_autoupdate_enabled = Mock(return_value=False)
        self.assertEqual(None, self.update_handler.get_latest_agent_greater_than_daemon())

    def test_get_latest_agent_skips_unavailable(self):
        self.prepare_agents()
        prior_agent = self.update_handler.get_latest_agent_greater_than_daemon()

        latest_version = self.prepare_agents(count=self.agent_count() + 1, is_available=False)
        latest_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, latest_version))
        self.assertFalse(GuestAgent.from_installed_agent(latest_path).is_available)

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertTrue(latest_agent.version < latest_version)
        self.assertEqual(latest_agent.version, prior_agent.version)

    def test_get_pid_files(self):
        pid_files = self.update_handler._get_pid_files()
        self.assertEqual(0, len(pid_files))

    def test_get_pid_files_returns_previous(self):
        for n in range(1250):
            fileutil.write_file(os.path.join(self.tmp_dir, str(n) + "_waagent.pid"), ustr(n + 1))
        pid_files = self.update_handler._get_pid_files()
        self.assertEqual(1250, len(pid_files))

        pid_dir, pid_name, pid_re = self.update_handler._get_pid_parts()  # pylint: disable=unused-variable
        for p in pid_files:
            self.assertTrue(pid_re.match(os.path.basename(p)))

    def test_is_clean_start_returns_true_when_no_sentinel(self):
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))
        self.assertTrue(self.update_handler._is_clean_start)

    def test_is_clean_start_returns_false_when_sentinel_exists(self):
        self.update_handler._set_sentinel(agent=CURRENT_AGENT)
        self.assertFalse(self.update_handler._is_clean_start)

    def test_is_clean_start_returns_false_for_exceptions(self):
        self.update_handler._set_sentinel()
        with patch("azurelinuxagent.common.utils.fileutil.read_file", side_effect=Exception):
            self.assertFalse(self.update_handler._is_clean_start)

    def test_is_orphaned_returns_false_if_parent_exists(self):
        fileutil.write_file(conf.get_agent_pid_file_path(), ustr(42))
        with patch('os.getppid', return_value=42):
            self.assertFalse(self.update_handler._is_orphaned)

    def test_is_orphaned_returns_true_if_parent_is_init(self):
        with patch('os.getppid', return_value=1):
            self.assertTrue(self.update_handler._is_orphaned)

    def test_is_orphaned_returns_true_if_parent_does_not_exist(self):
        fileutil.write_file(conf.get_agent_pid_file_path(), ustr(24))
        with patch('os.getppid', return_value=42):
            self.assertTrue(self.update_handler._is_orphaned)

    def test_purge_agents(self):
        self.prepare_agents()
        self.update_handler._find_agents()

        # Ensure at least three agents initially exist
        self.assertTrue(2 < len(self.update_handler.agents))

        # Purge every other agent. Don't add the current version to agents_to_keep explicitly;
        # the current version is never purged
        agents_to_keep = []
        kept_agents = []
        purged_agents = []
        for i in range(0, len(self.update_handler.agents)):
            if self.update_handler.agents[i].version == CURRENT_VERSION:
                kept_agents.append(self.update_handler.agents[i])
            else:
                if i % 2 == 0:
                    agents_to_keep.append(self.update_handler.agents[i])
                    kept_agents.append(self.update_handler.agents[i])
                else:
                    purged_agents.append(self.update_handler.agents[i])

        # Reload and assert only the kept agents remain on disk
        self.update_handler.agents = agents_to_keep
        self.update_handler._purge_agents()
        self.update_handler._find_agents()
        self.assertEqual(
            [agent.version for agent in kept_agents],
            [agent.version for agent in self.update_handler.agents])

        # Ensure both directories and packages are removed
        for agent in purged_agents:
            agent_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, agent.version))
            self.assertFalse(os.path.exists(agent_path))
            self.assertFalse(os.path.exists(agent_path + ".zip"))

        # Ensure kept agent directories and packages remain
        for agent in kept_agents:
            agent_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, agent.version))
            self.assertTrue(os.path.exists(agent_path))
            self.assertTrue(os.path.exists(agent_path + ".zip"))

    def _test_run_latest(self, mock_child=None, mock_time=None, child_args=None):
        if mock_child is None:
            mock_child = ChildMock()
        if mock_time is None:
            mock_time = TimeMock()

        with patch('azurelinuxagent.ga.update.subprocess.Popen', return_value=mock_child) as mock_popen:
            with patch('time.time', side_effect=mock_time.time):
                with patch('time.sleep', side_effect=mock_time.sleep):
                    self.update_handler.run_latest(child_args=child_args)
                    agent_calls = [args[0] for (args, _) in mock_popen.call_args_list if
                                   "run-exthandlers" in ''.join(args[0])]
                    self.assertEqual(1, len(agent_calls),
                                     "Expected a single call to the latest agent; got: {0}. All mocked calls: {1}".format(
                                         agent_calls, mock_popen.call_args_list))

                    return mock_popen.call_args

    def test_run_latest(self):
        self.prepare_agents()

        agent = self.update_handler.get_latest_agent_greater_than_daemon()
        args, kwargs = self._test_run_latest()
        args = args[0]
        cmds = textutil.safe_shlex_split(agent.get_agent_cmd())
        if cmds[0].lower() == "python":
            cmds[0] = sys.executable

        self.assertEqual(args, cmds)
        self.assertTrue(len(args) > 1)
        self.assertRegex(args[0], r"^(/.*/python[\d.]*)$", "The command doesn't contain full python path")
        self.assertEqual("-run-exthandlers", args[len(args) - 1])
        self.assertEqual(True, 'cwd' in kwargs)
        self.assertEqual(agent.get_agent_dir(), kwargs['cwd'])
        self.assertEqual(False, '\x00' in cmds[0])

    def test_run_latest_passes_child_args(self):
        self.prepare_agents()

        self.update_handler.get_latest_agent_greater_than_daemon()
        args, _ = self._test_run_latest(child_args="AnArgument")
        args = args[0]

        self.assertTrue(len(args) > 1)
        self.assertRegex(args[0], r"^(/.*/python[\d.]*)$", "The command doesn't contain full python path")
        self.assertEqual("AnArgument", args[len(args) - 1])

    def test_run_latest_polls_and_waits_for_success(self):
        mock_child = ChildMock(return_value=None)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL / 3)
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(2, mock_child.poll.call_count)
        self.assertEqual(1, mock_child.wait.call_count)

    def test_run_latest_polling_stops_at_success(self):
        mock_child = ChildMock(return_value=0)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL / 3)
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(1, mock_child.poll.call_count)
        self.assertEqual(0, mock_child.wait.call_count)

    def test_run_latest_polling_stops_at_failure(self):
        mock_child = ChildMock(return_value=42)
        mock_time = TimeMock()
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(1, mock_child.poll.call_count)
        self.assertEqual(0, mock_child.wait.call_count)

    def test_run_latest_polls_frequently_if_installed_is_latest(self):
        mock_child = ChildMock(return_value=0)  # pylint: disable=unused-variable
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL / 2)
        self._test_run_latest(mock_time=mock_time)
        self.assertEqual(1, mock_time.sleep_interval)

    def test_run_latest_polls_every_second_if_installed_not_latest(self):
        self.prepare_agents()

        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL / 2)
        self._test_run_latest(mock_time=mock_time)
        self.assertEqual(1, mock_time.sleep_interval)

    def test_run_latest_defaults_to_current(self):
        self.assertEqual(None, self.update_handler.get_latest_agent_greater_than_daemon())

        args, kwargs = self._test_run_latest()

        self.assertEqual(args[0], [sys.executable, "-u", sys.argv[0], "-run-exthandlers"])
        self.assertEqual(True, 'cwd' in kwargs)
        self.assertEqual(os.getcwd(), kwargs['cwd'])

    def test_run_latest_forwards_output(self):
        try:
            tempdir = tempfile.mkdtemp()
            stdout_path = os.path.join(tempdir, "stdout")
            stderr_path = os.path.join(tempdir, "stderr")

            with open(stdout_path, "w") as stdout:
                with open(stderr_path, "w") as stderr:
                    saved_stdout, sys.stdout = sys.stdout, stdout
                    saved_stderr, sys.stderr = sys.stderr, stderr
                    try:
                        self._test_run_latest(mock_child=ChildMock(side_effect=faux_logger))
                    finally:
                        sys.stdout = saved_stdout
                        sys.stderr = saved_stderr

            with open(stdout_path, "r") as stdout:
                self.assertEqual(1, len(stdout.readlines()))
            with open(stderr_path, "r") as stderr:
                self.assertEqual(1, len(stderr.readlines()))
        finally:
            shutil.rmtree(tempdir, True)

    def test_run_latest_nonzero_code_does_not_mark_failure(self):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent_greater_than_daemon', return_value=latest_agent):
            self._test_run_latest(mock_child=ChildMock(return_value=1))

        self.assertFalse(latest_agent.is_blacklisted, "Agent should not be blacklisted")

    def test_run_latest_exception_blacklists(self):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)
        verify_string = "Force blacklisting: {0}".format(str(uuid.uuid4()))

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent_greater_than_daemon', return_value=latest_agent):
            self._test_run_latest(mock_child=ChildMock(side_effect=Exception(verify_string)))

        self.assertFalse(latest_agent.is_available)
        self.assertTrue(latest_agent.error.is_blacklisted)
        self.assertNotEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)
        self.assertIn(verify_string, latest_agent.error.reason, "Error reason not found while blacklisting")

    def test_run_latest_exception_does_not_blacklist_if_terminating(self):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent_greater_than_daemon', return_value=latest_agent):
            self.update_handler.is_running = False
            self._test_run_latest(mock_child=ChildMock(side_effect=Exception("Attempt blacklisting")))

        self.assertTrue(latest_agent.is_available)
        self.assertFalse(latest_agent.error.is_blacklisted)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

    @patch('signal.signal')
    def test_run_latest_captures_signals(self, mock_signal):
        self._test_run_latest()
        self.assertEqual(1, mock_signal.call_count)

    @patch('signal.signal')
    def test_run_latest_creates_only_one_signal_handler(self, mock_signal):
        self.update_handler.signal_handler = "Not None"
        self._test_run_latest()
        self.assertEqual(0, mock_signal.call_count)

    def test_get_latest_agent_should_return_latest_agent_even_on_bad_error_json(self):
        dst_ver = self.prepare_agents()
        # Add a malformed error.json file in all existing agents
        for agent_dir in self.agent_dirs():
            error_file_path = os.path.join(agent_dir, AGENT_ERROR_FILE)
            with open(error_file_path, 'w') as f:
                f.write("")

        latest_agent = self.update_handler.get_latest_agent_greater_than_daemon()
        self.assertEqual(latest_agent.version, dst_ver, "Latest agent version is invalid")

    def test_set_agents_sets_agents(self):
        self.prepare_agents()

        self.update_handler._set_and_sort_agents([GuestAgent.from_installed_agent(path) for path in self.agent_dirs()])
        self.assertTrue(len(self.update_handler.agents) > 0)
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))

    def test_set_agents_sorts_agents(self):
        self.prepare_agents()

        self.update_handler._set_and_sort_agents([GuestAgent.from_installed_agent(path) for path in self.agent_dirs()])

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version

    def test_set_sentinel(self):
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))
        self.update_handler._set_sentinel()
        self.assertTrue(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_set_sentinel_writes_current_agent(self):
        self.update_handler._set_sentinel()
        self.assertTrue(
            fileutil.read_file(self.update_handler._sentinel_file_path()),
            CURRENT_AGENT)

    def test_shutdown(self):
        self.update_handler._set_sentinel()
        self.update_handler._shutdown()
        self.assertFalse(self.update_handler.is_running)
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_shutdown_ignores_missing_sentinel_file(self):
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))
        self.update_handler._shutdown()
        self.assertFalse(self.update_handler.is_running)
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_shutdown_ignores_exceptions(self):
        self.update_handler._set_sentinel()

        try:
            with patch("os.remove", side_effect=Exception):
                self.update_handler._shutdown()
        except Exception as e:  # pylint: disable=unused-variable
            self.assertTrue(False, "Unexpected exception")  # pylint: disable=redundant-unittest-assert

    def test_write_pid_file(self):
        for n in range(1112):
            fileutil.write_file(os.path.join(self.tmp_dir, str(n) + "_waagent.pid"), ustr(n + 1))
        with patch('os.getpid', return_value=1112):
            pid_files, pid_file = self.update_handler._write_pid_file()
            self.assertEqual(1112, len(pid_files))
            self.assertEqual("1111_waagent.pid", os.path.basename(pid_files[-1]))
            self.assertEqual("1112_waagent.pid", os.path.basename(pid_file))
            self.assertEqual(fileutil.read_file(pid_file), ustr(1112))

    def test_write_pid_file_ignores_exceptions(self):
        with patch('azurelinuxagent.common.utils.fileutil.write_file', side_effect=Exception):
            with patch('os.getpid', return_value=42):
                pid_files, pid_file = self.update_handler._write_pid_file()
                self.assertEqual(0, len(pid_files))
                self.assertEqual(None, pid_file)

    def test_update_happens_when_extensions_disabled(self):
        """
        Although the extension enabled config will not get checked
        before an update is found, this test attempts to ensure that
        behavior never changes.
        """
        with patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False):
            with patch('azurelinuxagent.ga.agent_update_handler.AgentUpdateHandler.run') as download_agent:
                with mock_wire_protocol(DATA_FILE) as protocol:
                    with mock_update_handler(protocol, autoupdate_enabled=True) as update_handler:
                        update_handler.run()

                        self.assertEqual(1, download_agent.call_count, "Agent update did not execute (no attempts to download the agent")

    @staticmethod
    def _get_test_ext_handler_instance(protocol, name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0"):
        eh = Extension(name=name)
        eh.version = version
        return ExtHandlerInstance(eh, protocol)

    def test_update_handler_recovers_from_error_with_no_certs(self):
        data = DATA_FILE.copy()
        data['goal_state'] = 'wire/goal_state_no_certs.xml'

        def fail_gs_fetch(url, *_, **__):
            if HttpRequestPredicates.is_goal_state_request(url):
                return MockHttpResponse(status=500)
            return None

        with mock_wire_protocol(data) as protocol:

            def fail_fetch_on_second_iter(iteration):
                if iteration == 2:
                    protocol.set_http_handlers(http_get_handler=fail_gs_fetch)
                if iteration > 2: # Zero out the fail handler for subsequent iterations.
                    protocol.set_http_handlers(http_get_handler=None)

            with mock_update_handler(protocol, 3, on_new_iteration=fail_fetch_on_second_iter) as update_handler:
                with patch("azurelinuxagent.ga.update.logger.error") as patched_error:
                    with patch("azurelinuxagent.ga.update.logger.info") as patched_info:
                        def match_unexpected_errors():
                            unexpected_msg_fragment = "Error fetching the goal state:"

                            matching_errors = []
                            for (args, _) in filter(lambda a: len(a) > 0, patched_error.call_args_list):
                                if unexpected_msg_fragment in args[0]:
                                    matching_errors.append(args[0])

                            if len(matching_errors) > 1:
                                self.fail("Guest Agent did not recover, with new error(s): {}"\
                                    .format(matching_errors[1:]))

                        def match_expected_info():
                            expected_msg_fragment = "Fetching the goal state recovered from previous errors"

                            for (call_args, _) in filter(lambda a: len(a) > 0, patched_info.call_args_list):
                                if expected_msg_fragment in call_args[0]:
                                    break
                            else:
                                self.fail("Expected the guest agent to recover with '{}', but it didn't"\
                                    .format(expected_msg_fragment))

                        update_handler.run(debug=True)
                        match_unexpected_errors() # Match on errors first, they can provide more info.
                        match_expected_info()


    def test_it_should_recreate_handler_env_on_service_startup(self):
        iterations = 5

        with _get_update_handler(iterations, autoupdate_enabled=False) as (update_handler, protocol):
            update_handler.run(debug=True)

            expected_handler = self._get_test_ext_handler_instance(protocol)
            handler_env_file = expected_handler.get_env_file()

            self.assertTrue(os.path.exists(expected_handler.get_base_dir()), "Extension not found")
            # First iteration should install the extension handler and
            # subsequent iterations should not recreate the HandlerEnvironment file
            last_modification_time = os.path.getmtime(handler_env_file)
            self.assertEqual(os.path.getctime(handler_env_file), last_modification_time,
                             "The creation time and last modified time of the HandlerEnvironment file dont match")

        # Simulate a service restart by getting a new instance of the update handler and protocol and
        # re-runnning the update handler. Then,ensure that the HandlerEnvironment file is recreated with eventsFolder
        # flag in HandlerEnvironment.json file.
        self._add_write_permission_to_goal_state_files()
        with _get_update_handler(iterations=1, autoupdate_enabled=False) as (update_handler, protocol):
            with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
                update_handler.run(debug=True)

            self.assertGreater(os.path.getmtime(handler_env_file), last_modification_time,
                                "HandlerEnvironment file didn't get overwritten")

            with open(handler_env_file, 'r') as handler_env_content_file:
                content = json.load(handler_env_content_file)
            self.assertIn(HandlerEnvironment.eventsFolder, content[0][HandlerEnvironment.handlerEnvironment],
                          "{0} not found in HandlerEnv file".format(HandlerEnvironment.eventsFolder))

    def test_it_should_not_setup_persistent_firewall_rules_if_EnableFirewall_is_disabled(self):
        executed_firewall_commands = []

        def _mock_popen(cmd, *args, **kwargs):
            if 'firewall-cmd' in cmd:
                executed_firewall_commands.append(cmd)
                cmd = ["echo", "running"]
            return _ORIGINAL_POPEN(cmd, *args, **kwargs)

        with _get_update_handler(iterations=1) as (update_handler, _):
            with patch("azurelinuxagent.common.logger.info") as patch_info:
                with patch("azurelinuxagent.common.utils.shellutil.subprocess.Popen", side_effect=_mock_popen):
                    with patch('azurelinuxagent.common.conf.enable_firewall', return_value=False):
                        with patch("azurelinuxagent.common.logger.warn") as patch_warn:
                            update_handler.run(debug=True)

        self.assertEqual(0, update_handler.get_exit_code(), "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
            patch_warn.call_args_list))
        self.assertEqual(0, len(executed_firewall_commands), "firewall-cmd should not be called at all")
        self.assertTrue(any(
            "Not setting up persistent firewall rules as OS.EnableFirewall=False" == args[0] for (args, _) in
            patch_info.call_args_list), "Info not logged properly, got: {0}".format(patch_info.call_args_list))

    @skip_if_predicate_true(is_python_version_26_or_34, "Disabled on Python 2.6 and 3.4 for now. Need to revisit to fix it")
    def test_it_should_setup_persistent_firewall_rules_on_startup(self):
        iterations = 1
        executed_commands = []

        def _mock_popen(cmd, *args, **kwargs):
            if 'firewall-cmd' in cmd:
                executed_commands.append(cmd)
                cmd = ["echo", "running"]
            return _ORIGINAL_POPEN(cmd, *args, **kwargs)

        with _get_update_handler(iterations) as (update_handler, _):
            with patch("azurelinuxagent.common.utils.shellutil.subprocess.Popen", side_effect=_mock_popen) as mock_popen:
                with patch('azurelinuxagent.common.conf.enable_firewall', return_value=True):
                    with patch('azurelinuxagent.common.osutil.systemd.is_systemd', return_value=True):
                        with patch("azurelinuxagent.common.logger.warn") as patch_warn:
                            update_handler.run(debug=True)

        self.assertEqual(0, update_handler.get_exit_code(), "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
            patch_warn.call_args_list))

        # Firewall-cmd should only be called 4 times - 1st to check if running, 2nd, 3rd and 4th for the QueryPassThrough cmd
        self.assertEqual(4, len(executed_commands),
                         "The number of times firewall-cmd should be called is only 4; Executed firewall commands: {0}; All popen calls: {1}".format(
                             executed_commands, mock_popen.call_args_list))
        self.assertEqual(PersistFirewallRulesHandler._FIREWALLD_RUNNING_CMD, executed_commands.pop(0),
                         "First command should be to check if firewalld is running")
        self.assertTrue([FirewallCmdDirectCommands.QueryPassThrough in cmd for cmd in executed_commands],
                        "The remaining commands should only be for querying the firewall commands")

    def test_it_should_set_dns_tcp_iptable_if_drop_available_accept_unavailable(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with _get_update_handler(test_data=DATA_FILE) as (update_handler, _):
                with patch('azurelinuxagent.common.conf.enable_firewall', return_value=True):
                    with patch.object(osutil, '_enable_firewall', True):
                        # drop rule is present
                        mock_iptables.set_command(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait), exit_code=0)
                        # non root tcp iptable rule is absent
                        mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND,
                                                                                       mock_iptables.destination,
                                                                                       wait=mock_iptables.wait),
                                                  exit_code=1)

                        update_handler._add_accept_tcp_firewall_rule_if_not_enabled(mock_iptables.destination)

                        drop_check_command = TestOSUtil._command_to_string(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait))
                        accept_tcp_check_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))
                        accept_tcp_insert_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.INSERT_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))

                        # Filtering the mock iptable command calls with only the ones related to this test.
                        filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if
                                                       cmd in [drop_check_command, accept_tcp_check_rule,
                                                               accept_tcp_insert_rule]]

                        self.assertEqual(len(filtered_mock_iptable_calls), 3,
                                         "Incorrect number of calls to iptables: [{0}]".format(
                                             mock_iptables.command_calls))
                        self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                         "The first command should check the drop rule")
                        self.assertEqual(filtered_mock_iptable_calls[1], accept_tcp_check_rule,
                                         "The second command should check the accept rule")
                        self.assertEqual(filtered_mock_iptable_calls[2], accept_tcp_insert_rule,
                                         "The third command should add the accept rule")

    def test_it_should_not_set_dns_tcp_iptable_if_drop_unavailable(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with _get_update_handler(test_data=DATA_FILE) as (update_handler, _):
                with patch('azurelinuxagent.common.conf.enable_firewall', return_value=True):
                    with patch.object(osutil, '_enable_firewall', True):
                        # drop rule is not available
                        mock_iptables.set_command(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait), exit_code=1)

                        update_handler._add_accept_tcp_firewall_rule_if_not_enabled(mock_iptables.destination)

                        drop_check_command = TestOSUtil._command_to_string(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait))
                        accept_tcp_check_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))
                        accept_tcp_insert_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.INSERT_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))

                        # Filtering the mock iptable command calls with only the ones related to this test.
                        filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if
                                                       cmd in [drop_check_command, accept_tcp_check_rule,
                                                               accept_tcp_insert_rule]]

                        self.assertEqual(len(filtered_mock_iptable_calls), 1,
                                         "Incorrect number of calls to iptables: [{0}]".format(
                                             mock_iptables.command_calls))
                        self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                         "The first command should check the drop rule")

    def test_it_should_not_set_dns_tcp_iptable_if_drop_and_accept_available(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with _get_update_handler(test_data=DATA_FILE) as (update_handler, _):
                with patch('azurelinuxagent.common.conf.enable_firewall', return_value=True):
                    with patch.object(osutil, '_enable_firewall', True):
                        # drop rule is available
                        mock_iptables.set_command(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait), exit_code=0)
                        # non root tcp iptable rule is available
                        mock_iptables.set_command(AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND,
                                                                                       mock_iptables.destination,
                                                                                       wait=mock_iptables.wait),
                                                  exit_code=0)

                        update_handler._add_accept_tcp_firewall_rule_if_not_enabled(mock_iptables.destination)

                        drop_check_command = TestOSUtil._command_to_string(
                            AddFirewallRules.get_wire_non_root_drop_rule(AddFirewallRules.CHECK_COMMAND,
                                                                         mock_iptables.destination,
                                                                         wait=mock_iptables.wait))
                        accept_tcp_check_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.CHECK_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))
                        accept_tcp_insert_rule = TestOSUtil._command_to_string(
                            AddFirewallRules.get_accept_tcp_rule(AddFirewallRules.INSERT_COMMAND,
                                                                 mock_iptables.destination,
                                                                 wait=mock_iptables.wait))

                        # Filtering the mock iptable command calls with only the ones related to this test.
                        filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if
                                                       cmd in [drop_check_command, accept_tcp_check_rule,
                                                               accept_tcp_insert_rule]]

                        self.assertEqual(len(filtered_mock_iptable_calls), 2,
                                         "Incorrect number of calls to iptables: [{0}]".format(
                                             mock_iptables.command_calls))
                        self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                         "The first command should check the drop rule")
                        self.assertEqual(filtered_mock_iptable_calls[1], accept_tcp_check_rule,
                                         "The second command should check the accept rule")

    @contextlib.contextmanager
    def _setup_test_for_ext_event_dirs_retention(self):
        try:
            with _get_update_handler(test_data=DATA_FILE_MULTIPLE_EXT, autoupdate_enabled=False) as (update_handler, protocol):
                with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
                    update_handler.run(debug=True)
                    expected_events_dirs = glob.glob(os.path.join(conf.get_ext_log_dir(), "*", EVENTS_DIRECTORY))
                    no_of_extensions = protocol.mock_wire_data.get_no_of_plugins_in_extension_config()
                    # Ensure extensions installed and events directory created
                    self.assertEqual(len(expected_events_dirs), no_of_extensions, "Extension events directories dont match")
                    for ext_dir in expected_events_dirs:
                        self.assertTrue(os.path.exists(ext_dir), "Extension directory {0} not created!".format(ext_dir))

                    yield update_handler, expected_events_dirs
        finally:
            # The TestUpdate.setUp() initializes the self.tmp_dir to be used as a placeholder
            # for everything (event logger, status logger, conf.get_lib_dir() and more).
            # Since we add more data to the dir for this test, ensuring its completely clean before exiting the test.
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
            self.tmp_dir = None

    def test_it_should_delete_extension_events_directory_if_extension_telemetry_pipeline_disabled(self):
        # Disable extension telemetry pipeline and ensure events directory got deleted
        with self._setup_test_for_ext_event_dirs_retention() as (update_handler, expected_events_dirs):
            with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", False):
                self._add_write_permission_to_goal_state_files()
                update_handler.run(debug=True)
                for ext_dir in expected_events_dirs:
                    self.assertFalse(os.path.exists(ext_dir), "Extension directory {0} still exists!".format(ext_dir))

    def test_it_should_retain_extension_events_directories_if_extension_telemetry_pipeline_enabled(self):
        # Rerun update handler again with extension telemetry pipeline enabled to ensure we dont delete events directories
        with self._setup_test_for_ext_event_dirs_retention() as (update_handler, expected_events_dirs):
            self._add_write_permission_to_goal_state_files()
            update_handler.run(debug=True)
            for ext_dir in expected_events_dirs:
                self.assertTrue(os.path.exists(ext_dir), "Extension directory {0} should exist!".format(ext_dir))

    def test_it_should_recreate_extension_event_directories_for_existing_extensions_if_extension_telemetry_pipeline_enabled(self):
        with self._setup_test_for_ext_event_dirs_retention() as (update_handler, expected_events_dirs):
            # Delete existing events directory
            for ext_dir in expected_events_dirs:
                shutil.rmtree(ext_dir, ignore_errors=True)
                self.assertFalse(os.path.exists(ext_dir), "Extension directory not deleted")

            with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
                self._add_write_permission_to_goal_state_files()
                update_handler.run(debug=True)
                for ext_dir in expected_events_dirs:
                    self.assertTrue(os.path.exists(ext_dir), "Extension directory {0} should exist!".format(ext_dir))

    def test_it_should_report_update_status_in_status_blob(self):
        with mock_wire_protocol(DATA_FILE) as protocol:
            with patch.object(conf, "get_autoupdate_gafamily", return_value="Prod"):
                with patch("azurelinuxagent.common.conf.get_enable_ga_versioning", return_value=True):
                    with patch("azurelinuxagent.common.logger.warn") as patch_warn:

                        protocol.aggregate_status = None
                        protocol.incarnation = 1

                        def get_handler(url, **kwargs):
                            if HttpRequestPredicates.is_agent_package_request(url):
                                return MockHttpResponse(status=httpclient.SERVICE_UNAVAILABLE)
                            return protocol.mock_wire_data.mock_http_get(url, **kwargs)

                        def put_handler(url, *args, **_):
                            if HttpRequestPredicates.is_host_plugin_status_request(url):
                                # Skip reading the HostGA request data as its encoded
                                return MockHttpResponse(status=500)
                            protocol.aggregate_status = json.loads(args[0])
                            return MockHttpResponse(status=201)

                        def update_goal_state_and_run_handler(autoupdate_enabled = True):
                            protocol.incarnation += 1
                            protocol.mock_wire_data.set_incarnation(protocol.incarnation)
                            self._add_write_permission_to_goal_state_files()
                            with _get_update_handler(iterations=1, protocol=protocol, autoupdate_enabled=autoupdate_enabled) as (update_handler, _):
                                GAUpdateReportState.report_error_msg = ""
                                update_handler.run(debug=True)
                            self.assertEqual(0, update_handler.get_exit_code(),
                                             "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
                                                 patch_warn.call_args_list))

                        protocol.set_http_handlers(http_get_handler=get_handler, http_put_handler=put_handler)

                        # Case 1: Requested version removed in GS; report missing requested version errr
                        protocol.mock_wire_data.set_extension_config("wire/ext_conf.xml")
                        protocol.mock_wire_data.reload()
                        update_goal_state_and_run_handler()
                        self.assertTrue("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                         "updateStatus should be reported")
                        update_status = protocol.aggregate_status['aggregateStatus']['guestAgentStatus']["updateStatus"]
                        self.assertEqual(VMAgentUpdateStatuses.Error, update_status['status'], "Status should be an error")
                        self.assertEqual(update_status['code'], 1, "incorrect code reported")
                        self.assertIn("Missing requested version", update_status['formattedMessage']['message'], "incorrect message reported")

                        # Case 2: Requested version in GS == Current Version; updateStatus should be Success
                        protocol.mock_wire_data.set_extension_config("wire/ext_conf_requested_version.xml")
                        protocol.mock_wire_data.set_extension_config_requested_version(str(CURRENT_VERSION))
                        update_goal_state_and_run_handler()
                        self.assertTrue("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                        "updateStatus should be reported if asked in GS")
                        update_status = protocol.aggregate_status['aggregateStatus']['guestAgentStatus']["updateStatus"]
                        self.assertEqual(VMAgentUpdateStatuses.Success, update_status['status'], "Status should be successful")
                        self.assertEqual(update_status['expectedVersion'], str(CURRENT_VERSION), "incorrect version reported")
                        self.assertEqual(update_status['code'], 0, "incorrect code reported")

                        # Case 3: Requested version in GS != Current Version; update fail and report error
                        protocol.mock_wire_data.set_extension_config("wire/ext_conf_requested_version.xml")
                        protocol.mock_wire_data.set_extension_config_requested_version("5.2.0.1")
                        update_goal_state_and_run_handler()
                        self.assertTrue("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                        "updateStatus should be in status blob. Warns: {0}".format(patch_warn.call_args_list))
                        update_status = protocol.aggregate_status['aggregateStatus']['guestAgentStatus']["updateStatus"]
                        self.assertEqual(VMAgentUpdateStatuses.Error, update_status['status'], "Status should be an error")
                        self.assertEqual(update_status['expectedVersion'], "5.2.0.1", "incorrect version reported")
                        self.assertEqual(update_status['code'], 1, "incorrect code reported")

    def test_it_should_wait_to_fetch_first_goal_state(self):
        with _get_update_handler() as (update_handler, protocol):
            with patch("azurelinuxagent.common.logger.error") as patch_error:
                with patch("azurelinuxagent.common.logger.info") as patch_info:
                    # Fail GS fetching for the 1st 5 times the agent asks for it
                    update_handler._fail_gs_count = 5

                    def get_handler(url, **kwargs):
                        if HttpRequestPredicates.is_goal_state_request(url) and update_handler._fail_gs_count > 0:
                            update_handler._fail_gs_count -= 1
                            return MockHttpResponse(status=500)
                        return protocol.mock_wire_data.mock_http_get(url, **kwargs)

                    protocol.set_http_handlers(http_get_handler=get_handler)
                    update_handler.run(debug=True)

        self.assertEqual(0, update_handler.get_exit_code(), "Exit code should be 0; List of all errors logged by the agent: {0}".format(
            patch_error.call_args_list))

        error_msgs = [args[0] for (args, _) in patch_error.call_args_list if
                     "Error fetching the goal state" in args[0]]
        self.assertTrue(len(error_msgs) > 0, "Error should've been reported when failed to retrieve GS")

        info_msgs = [args[0] for (args, _) in patch_info.call_args_list if
                     "Fetching the goal state recovered from previous errors." in args[0]]
        self.assertTrue(len(info_msgs) > 0, "Agent should've logged a message when recovered from GS errors")

    def test_it_should_reset_legacy_blacklisted_agents_on_process_start(self):
        # Add some good agents
        self.prepare_agents(count=10)
        good_agents = [agent.name for agent in self.agents()]

        # Add a set of blacklisted agents
        self.prepare_agents(count=20, is_available=False)
        for agent in self.agents():
            # Assert the test environment is correctly set
            if agent.name not in good_agents:
                self.assertTrue(agent.is_blacklisted, "Agent {0} should be blacklisted".format(agent.name))
            else:
                self.assertFalse(agent.is_blacklisted, "Agent {0} should not be blacklisted".format(agent.name))

        with _get_update_handler(autoupdate_enabled=False) as (update_handler, _):
            update_handler.run(debug=True)
            self.assertEqual(20, self.agent_count(), "All agents should be available on disk")
            # Ensure none of the agents are blacklisted
            for agent in self.agents():
                self.assertFalse(agent.is_blacklisted, "Legacy Agent should not be blacklisted")


class UpdateHandlerRunTestCase(AgentTestCase):
    def _test_run(self, autoupdate_enabled=False, check_daemon_running=False, expected_exit_code=0, emit_restart_event=None):
        fileutil.write_file(conf.get_agent_pid_file_path(), ustr(42))

        with patch('azurelinuxagent.ga.update.get_monitor_handler') as mock_monitor:
            with patch('azurelinuxagent.ga.remoteaccess.get_remote_access_handler') as mock_ra_handler:
                with patch('azurelinuxagent.ga.update.get_env_handler') as mock_env:
                    with patch('azurelinuxagent.ga.update.get_collect_logs_handler') as mock_collect_logs:
                        with patch('azurelinuxagent.ga.update.get_send_telemetry_events_handler') as mock_telemetry_send_events:
                            with patch('azurelinuxagent.ga.update.get_collect_telemetry_events_handler') as mock_event_collector:
                                with patch('azurelinuxagent.ga.update.initialize_event_logger_vminfo_common_parameters'):
                                    with patch('azurelinuxagent.ga.update.is_log_collection_allowed', return_value=True):
                                        with mock_wire_protocol(DATA_FILE) as protocol:
                                            mock_exthandlers_handler = Mock()
                                            with mock_update_handler(
                                                    protocol,
                                                    exthandlers_handler=mock_exthandlers_handler,
                                                    remote_access_handler=mock_ra_handler,
                                                    autoupdate_enabled=autoupdate_enabled,
                                                    check_daemon_running=check_daemon_running
                                            ) as update_handler:

                                                if emit_restart_event is not None:
                                                    update_handler._emit_restart_event = emit_restart_event

                                                if isinstance(os.getppid, MagicMock):
                                                    update_handler.run()
                                                else:
                                                    with patch('os.getppid', return_value=42):
                                                        update_handler.run()

                                                self.assertEqual(1, mock_monitor.call_count)
                                                self.assertEqual(1, mock_env.call_count)
                                                self.assertEqual(1, mock_collect_logs.call_count)
                                                self.assertEqual(1, mock_telemetry_send_events.call_count)
                                                self.assertEqual(1, mock_event_collector.call_count)
                                                self.assertEqual(expected_exit_code, update_handler.get_exit_code())

                                                if update_handler.get_iterations_completed() > 0:  # some test cases exit before executing extensions or remote access
                                                    self.assertEqual(1, mock_exthandlers_handler.run.call_count)
                                                    self.assertEqual(1, mock_ra_handler.run.call_count)

                                                return update_handler

    def test_run(self):
        self._test_run()

    def test_run_stops_if_orphaned(self):
        with patch('os.getppid', return_value=1):
            update_handler = self._test_run(check_daemon_running=True)
            self.assertEqual(0, update_handler.get_iterations_completed())

    def test_run_clears_sentinel_on_successful_exit(self):
        update_handler = self._test_run()
        self.assertFalse(os.path.isfile(update_handler._sentinel_file_path()))

    def test_run_leaves_sentinel_on_unsuccessful_exit(self):
        with patch('azurelinuxagent.ga.agent_update_handler.AgentUpdateHandler.run', side_effect=Exception):
            update_handler = self._test_run(autoupdate_enabled=True,expected_exit_code=1)
            self.assertTrue(os.path.isfile(update_handler._sentinel_file_path()))

    def test_run_emits_restart_event(self):
        update_handler = self._test_run(emit_restart_event=Mock())
        self.assertEqual(1, update_handler._emit_restart_event.call_count)


class TestAgentUpgrade(UpdateTestCase):

    @contextlib.contextmanager
    def create_conf_mocks(self, autoupdate_frequency, hotfix_frequency, normal_frequency):
        # Disabling extension processing to speed up tests as this class deals with testing agent upgrades
        with patch("azurelinuxagent.common.conf.get_extensions_enabled", return_value=False):
            with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=autoupdate_frequency):
                with patch("azurelinuxagent.common.conf.get_hotfix_upgrade_frequency", return_value=hotfix_frequency):
                    with patch("azurelinuxagent.common.conf.get_normal_upgrade_frequency", return_value=normal_frequency):
                        with patch("azurelinuxagent.common.conf.get_autoupdate_gafamily", return_value="Prod"):
                            with patch("azurelinuxagent.common.conf.get_enable_ga_versioning", return_value=True):
                                yield

    @contextlib.contextmanager
    def __get_update_handler(self, iterations=1, test_data=None,
                             reload_conf=None, autoupdate_frequency=0.001, hotfix_frequency=1.0, normal_frequency=2.0):

        test_data = DATA_FILE if test_data is None else test_data

        with _get_update_handler(iterations, test_data) as (update_handler, protocol):

            protocol.aggregate_status = None

            def get_handler(url, **kwargs):
                if reload_conf is not None:
                    reload_conf(url, protocol)

                if HttpRequestPredicates.is_agent_package_request(url):
                    agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
                    protocol.mock_wire_data.call_counts['agentArtifact'] += 1
                    return MockHttpResponse(status=httpclient.OK, body=agent_pkg)
                return protocol.mock_wire_data.mock_http_get(url, **kwargs)

            def put_handler(url, *args, **_):
                if HttpRequestPredicates.is_host_plugin_status_request(url):
                    # Skip reading the HostGA request data as its encoded
                    return MockHttpResponse(status=500)
                protocol.aggregate_status = json.loads(args[0])
                return MockHttpResponse(status=201)

            protocol.set_http_handlers(http_get_handler=get_handler, http_put_handler=put_handler)
            with self.create_conf_mocks(autoupdate_frequency, hotfix_frequency, normal_frequency):
                with patch("azurelinuxagent.common.event.EventLogger.add_event") as mock_telemetry:
                    update_handler._protocol = protocol
                    yield update_handler, mock_telemetry

    def __assert_exit_code_successful(self, update_handler):
        self.assertEqual(0, update_handler.get_exit_code(), "Exit code should be 0")

    def __assert_upgrade_telemetry_emitted(self, mock_telemetry, upgrade=True, version="9.9.9.10"):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              'Agent update found, exiting current process to {0} to the new Agent version {1}'.format(
                                  "upgrade" if upgrade else "downgrade", version) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs),
                         "Did not find the event indicating that the agent was upgraded. Got: {0}".format(
                             mock_telemetry.call_args_list))

    def __assert_agent_directories_available(self, versions):
        for version in versions:
            self.assertTrue(os.path.exists(self.agent_dir(version)), "Agent directory {0} not found".format(version))

    def __assert_agent_directories_exist_and_others_dont_exist(self, versions):
        self.__assert_agent_directories_available(versions=versions)
        other_agents = [agent_dir for agent_dir in self.agent_dirs() if
                        agent_dir not in [self.agent_dir(version) for version in versions]]
        self.assertFalse(any(other_agents),
                         "All other agents should be purged from agent dir: {0}".format(other_agents))

    def __assert_ga_version_in_status(self, aggregate_status, version=str(CURRENT_VERSION)):
        self.assertIsNotNone(aggregate_status, "Status should be reported")
        self.assertEqual(aggregate_status['aggregateStatus']['guestAgentStatus']['version'], version,
                         "Status should be reported from the Current version")
        self.assertEqual(aggregate_status['aggregateStatus']['guestAgentStatus']['status'], 'Ready',
                         "Guest Agent should be reported as Ready")

    def test_it_should_upgrade_agent_on_process_start_if_auto_upgrade_enabled(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(test_data=data_file, iterations=10) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

            self.__assert_exit_code_successful(update_handler)
            self.assertEqual(1, update_handler.get_iterations(), "Update handler should've exited after the first run")
            self.__assert_agent_directories_available(versions=["9.9.9.10"])
            self.__assert_upgrade_telemetry_emitted(mock_telemetry)

    def test_it_should_not_update_agent_if_last_update_time_not_permitted(self):
        no_of_iterations = 10
        data_file = DATA_FILE.copy()
        data_file['ext_conf'] = "wire/ext_conf_requested_version.xml"

        self.prepare_agents(1)
        test_frequency = 10
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file,
                                       autoupdate_frequency=test_frequency) as (update_handler, _):
            update_handler._protocol.mock_wire_data.set_ga_manifest_version_version("5.2.0.1")
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.__assert_exit_code_successful(update_handler)
            self.assertEqual(no_of_iterations, update_handler.get_iterations(), "Update handler should've run its course")
            self.assertFalse(os.path.exists(self.agent_dir("5.2.0.1")),
                             "New agent directory should not be found")

    def test_it_should_not_auto_upgrade_if_auto_update_disabled(self):
        with self.__get_update_handler(iterations=10) as (update_handler, _):
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=False):
                update_handler.run(debug=True)

                self.__assert_exit_code_successful(update_handler)
                self.assertGreaterEqual(update_handler.get_iterations(), 10, "Update handler should've run 10 times")
                self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                                 "New agent directory should not be found")

    def test_it_should_download_only_requested_version_if_available(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(test_data=data_file) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

        self.__assert_exit_code_successful(update_handler)
        self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="9.9.9.10")
        self.__assert_agent_directories_exist_and_others_dont_exist(versions=["9.9.9.10"])

    def test_it_should_download_largest_version_if_ga_versioning_disabled(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(test_data=data_file) as (update_handler, mock_telemetry):
            with patch.object(conf, "get_enable_ga_versioning", return_value=False):
                update_handler.run(debug=True)

        self.__assert_exit_code_successful(update_handler)
        self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="99999.0.0.0")
        self.__assert_agent_directories_exist_and_others_dont_exist(versions=["99999.0.0.0"])

    def test_it_should_cleanup_all_agents_except_requested_version_and_current_version(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_update_handler(test_data=data_file) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

        self.__assert_exit_code_successful(update_handler)
        self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="9.9.9.10")
        self.__assert_agent_directories_exist_and_others_dont_exist(versions=["9.9.9.10", str(CURRENT_VERSION)])

    def test_it_should_not_update_if_requested_version_not_found_in_manifest(self):
        self.prepare_agents(1)
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version_missing_in_manifest.xml"
        with self.__get_update_handler(test_data=data_file) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

        self.__assert_exit_code_successful(update_handler)
        self.__assert_agent_directories_exist_and_others_dont_exist(versions=[str(CURRENT_VERSION)])
        agent_msgs = [kwarg for _, kwarg in mock_telemetry.call_args_list if
                      kwarg['op'] in (WALAEventOperation.AgentUpgrade, WALAEventOperation.Download)]
        # This will throw if corresponding message not found so not asserting on that
        requested_version_found = next(kwarg for kwarg in agent_msgs if
                                       "Goal state incarnation_1 is requesting a new agent version 5.2.1.0, will update the agent before processing the goal state" in kwarg['message'])
        self.assertTrue(requested_version_found['is_success'],
                        "The requested version found op should be reported as a success")

        skipping_update = next(kwarg for kwarg in agent_msgs if
                               "No matching package found in the agent manifest for requested version: 5.2.1.0 in goal state incarnation: incarnation_1, skipping agent update" in kwarg['message'])
        self.assertEqual(skipping_update['version'], str(CURRENT_VERSION),
                         "The not found message should be reported from current agent version")
        self.assertFalse(skipping_update['is_success'], "The not found op should be reported as a failure")

    def test_it_should_try_downloading_requested_version_on_new_incarnation(self):
        no_of_iterations = 1000

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        def reload_conf(url, protocol):
            mock_wire_data = protocol.mock_wire_data

            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_goal_state_request(url) and mock_wire_data.call_counts[
             "goalstate"] >= 10 and mock_wire_data.call_counts["goalstate"] < 15:

                # Ensure we didn't try to download any agents except during the incarnation change
                self.__assert_agent_directories_available(versions=[str(CURRENT_VERSION)])

                # Update the requested version to "99999.0.0.0"
                update_handler._protocol.mock_wire_data.set_extension_config_requested_version("99999.0.0.0")
                reload_conf.call_count += 1
                self._add_write_permission_to_goal_state_files()
                reload_conf.incarnation += 1
                mock_wire_data.set_incarnation(reload_conf.incarnation)

        reload_conf.call_count = 0
        reload_conf.incarnation = 2

        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, reload_conf=reload_conf) as (update_handler, mock_telemetry):
            update_handler._protocol.mock_wire_data.set_extension_config_requested_version(str(CURRENT_VERSION))
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.assertGreaterEqual(reload_conf.call_count, 1, "Reload conf not updated as expected")
            self.__assert_exit_code_successful(update_handler)
            self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="99999.0.0.0")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=["99999.0.0.0", str(CURRENT_VERSION)])
            self.assertEqual(update_handler._protocol.mock_wire_data.call_counts['agentArtifact'], 1,
                             "only 1 agent should've been downloaded - 1 per incarnation")
            self.assertGreaterEqual(update_handler._protocol.mock_wire_data.call_counts["manifest_of_ga.xml"], 1,
                             "only 1 agent manifest call should've been made - 1 per incarnation")

    def test_it_should_update_to_largest_version_if_requested_version_not_available(self):
        no_of_iterations = 100

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        def reload_conf(url, protocol):
            mock_wire_data = protocol.mock_wire_data

            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_goal_state_request(url) and mock_wire_data.call_counts[
             "goalstate"] >= 5:
                reload_conf.call_count += 1

                # By this point, the GS with requested version should've been executed. Verify that
                self.__assert_agent_directories_available(versions=[str(CURRENT_VERSION)])

                # Update the ext-conf and incarnation and remove requested versions from GS,
                # this should download all versions requested in config
                mock_wire_data.data_files["ext_conf"] = "wire/ext_conf.xml"
                mock_wire_data.reload()
                self._add_write_permission_to_goal_state_files()
                reload_conf.incarnation += 1
                mock_wire_data.set_incarnation(reload_conf.incarnation)

        reload_conf.call_count = 0
        reload_conf.incarnation = 2

        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, reload_conf=reload_conf) as (update_handler, mock_telemetry):
            update_handler._protocol.mock_wire_data.set_extension_config_requested_version(str(CURRENT_VERSION))
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Reload conf not updated")
            self.__assert_exit_code_successful(update_handler)
            self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="99999.0.0.0")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=["99999.0.0.0", str(CURRENT_VERSION)])

    def test_it_should_not_update_largest_version_if_time_window_not_elapsed(self):
        no_of_iterations = 20

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        def reload_conf(url, protocol):
            mock_wire_data = protocol.mock_wire_data

            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_goal_state_request(url) and mock_wire_data.call_counts[
             "goalstate"] >= 5:
                reload_conf.call_count += 1

                self.__assert_agent_directories_available(versions=[str(CURRENT_VERSION)])

                # Update the ga_manifest and incarnation to send largest version manifest
                mock_wire_data.data_files["ga_manifest"] = "wire/ga_manifest.xml"
                mock_wire_data.reload()
                self._add_write_permission_to_goal_state_files()
                reload_conf.incarnation += 1
                mock_wire_data.set_incarnation(reload_conf.incarnation)

        reload_conf.call_count = 0
        reload_conf.incarnation = 2

        data_file = wire_protocol_data.DATA_FILE.copy()
        # This is to fail the agent update at first attempt so that agent doesn't go through update
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, reload_conf=reload_conf,
                                       hotfix_frequency=10, normal_frequency=10) as (update_handler, _):
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Reload conf not updated")
            self.__assert_exit_code_successful(update_handler)
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

    def test_it_should_update_largest_version_if_time_window_elapsed(self):
        no_of_iterations = 20

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        def reload_conf(url, protocol):
            mock_wire_data = protocol.mock_wire_data

            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_goal_state_request(url) and mock_wire_data.call_counts[
             "goalstate"] >= 5:
                reload_conf.call_count += 1

                self.__assert_agent_directories_available(versions=[str(CURRENT_VERSION)])

                # Update the ga_manifest and incarnation to send largest version manifest
                mock_wire_data.data_files["ga_manifest"] = "wire/ga_manifest.xml"
                mock_wire_data.reload()
                self._add_write_permission_to_goal_state_files()
                reload_conf.incarnation += 1
                mock_wire_data.set_incarnation(reload_conf.incarnation)

        reload_conf.call_count = 0
        reload_conf.incarnation = 2

        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ga_manifest"] = "wire/ga_manifest_no_uris.xml"
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, reload_conf=reload_conf,
                                       hotfix_frequency=0.001, normal_frequency=0.001) as (update_handler, mock_telemetry):
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Reload conf not updated")
            self.__assert_exit_code_successful(update_handler)
            self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="99999.0.0.0")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=["99999.0.0.0", str(CURRENT_VERSION)])

    def test_it_should_not_download_anything_if_requested_version_is_current_version(self):
        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"

        # Set the test environment by adding 20 random agents to the agent directory
        self.prepare_agents()
        self.assertEqual(20, self.agent_count(), "Agent directories not set properly")

        with self.__get_update_handler(test_data=data_file) as (update_handler, _):
            update_handler._protocol.mock_wire_data.set_extension_config_requested_version(str(CURRENT_VERSION))
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.__assert_exit_code_successful(update_handler)
            self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                             "New agent directory should not be found")

    def test_it_should_skip_wait_to_update_if_requested_version_available(self):
        no_of_iterations = 100

        def reload_conf(url, protocol):
            mock_wire_data = protocol.mock_wire_data

            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_goal_state_request(url) and mock_wire_data.call_counts["goalstate"] >= 5:
                reload_conf.call_count += 1

                # Assert GA version from status to ensure agent is running fine from the current version
                self.__assert_ga_version_in_status(protocol.aggregate_status)

                # Update the ext-conf and incarnation and add requested version from GS
                mock_wire_data.data_files["ext_conf"] = "wire/ext_conf_requested_version.xml"
                data_file['ga_manifest'] = "wire/ga_manifest.xml"
                mock_wire_data.reload()
                self._add_write_permission_to_goal_state_files()
                mock_wire_data.set_incarnation(2)

        reload_conf.call_count = 0

        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file['ga_manifest'] = "wire/ga_manifest_no_upgrade.xml"
        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, reload_conf=reload_conf) as (update_handler, mock_telemetry):
            update_handler._protocol.mock_wire_data.set_ga_manifest_version_version(str(CURRENT_VERSION))
            update_handler._protocol.mock_wire_data.set_incarnation(20)
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Reload conf not updated")
            self.assertLess(update_handler.get_iterations(), no_of_iterations,
                            "The code should've exited as soon as requested version was found")
            self.__assert_exit_code_successful(update_handler)
            self.__assert_upgrade_telemetry_emitted(mock_telemetry, version="9.9.9.10")

    def test_it_should_mark_current_agent_as_bad_version_on_downgrade(self):
        # Create Agent directory for current agent
        self.prepare_agents(count=1)
        self.assertTrue(os.path.exists(self.agent_dir(CURRENT_VERSION)))
        self.assertFalse(next(agent for agent in self.agents() if agent.version == CURRENT_VERSION).is_blacklisted,
                         "The current agent should not be blacklisted")
        downgraded_version = "2.5.0"

        data_file = wire_protocol_data.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_requested_version.xml"
        with self.__get_update_handler(test_data=data_file) as (update_handler, mock_telemetry):
            update_handler._protocol.mock_wire_data.set_extension_config_requested_version(downgraded_version)
            update_handler._protocol.mock_wire_data.set_incarnation(2)
            update_handler.run(debug=True)

            self.__assert_exit_code_successful(update_handler)
            self.__assert_upgrade_telemetry_emitted(mock_telemetry, upgrade=False,
                                                                          version=downgraded_version)
            current_agent = next(agent for agent in self.agents() if agent.version == CURRENT_VERSION)
            self.assertTrue(current_agent.is_blacklisted, "The current agent should be blacklisted")
            self.assertEqual(current_agent.error.reason, "Marking the agent {0} as bad version since a downgrade was requested in the GoalState, "
                                                         "suggesting that we really don't want to execute any extensions using this version".format(CURRENT_VERSION),
                             "Invalid reason specified for blacklisting agent")
            self.__assert_agent_directories_exist_and_others_dont_exist(versions=[downgraded_version, str(CURRENT_VERSION)])


@patch('azurelinuxagent.ga.update.get_collect_telemetry_events_handler')
@patch('azurelinuxagent.ga.update.get_send_telemetry_events_handler')
@patch('azurelinuxagent.ga.update.get_collect_logs_handler')
@patch('azurelinuxagent.ga.update.get_monitor_handler')
@patch('azurelinuxagent.ga.update.get_env_handler')
class MonitorThreadTest(AgentTestCaseWithGetVmSizeMock):
    def setUp(self):
        super(MonitorThreadTest, self).setUp()
        self.event_patch = patch('azurelinuxagent.common.event.add_event')
        current_thread().name = "ExtHandler"
        protocol = Mock()
        self.update_handler = get_update_handler()
        self.update_handler.protocol_util = Mock()
        self.update_handler.protocol_util.get_protocol = Mock(return_value=protocol)
        clear_singleton_instances(ProtocolUtil)

    def _test_run(self, invocations=1):
        def iterator(*_, **__):
            iterator.count += 1
            if iterator.count <= invocations:
                return True
            return False
        iterator.count = 0

        with patch('os.getpid', return_value=42):
            with patch.object(UpdateHandler, '_is_orphaned') as mock_is_orphaned:
                mock_is_orphaned.__get__ = Mock(return_value=False)
                with patch.object(UpdateHandler, 'is_running') as mock_is_running:
                    mock_is_running.__get__ = Mock(side_effect=iterator)
                    with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler'):
                        with patch('azurelinuxagent.ga.remoteaccess.get_remote_access_handler'):
                            with patch('azurelinuxagent.ga.agent_update_handler.get_agent_update_handler'):
                                with patch('azurelinuxagent.ga.update.initialize_event_logger_vminfo_common_parameters'):
                                    with patch('azurelinuxagent.ga.cgroupapi.CGroupsApi.cgroups_supported', return_value=False):  # skip all cgroup stuff
                                        with patch('azurelinuxagent.ga.update.is_log_collection_allowed', return_value=True):
                                            with patch('time.sleep'):
                                                with patch('sys.exit'):
                                                    self.update_handler.run()

    def _setup_mock_thread_and_start_test_run(self, mock_thread, is_alive=True, invocations=0):
        thread = MagicMock()
        thread.run = MagicMock()
        thread.is_alive = MagicMock(return_value=is_alive)
        thread.start = MagicMock()
        mock_thread.return_value = thread

        self._test_run(invocations=invocations)
        return thread

    def test_start_threads(self, mock_env, mock_monitor, mock_collect_logs, mock_telemetry_send_events, mock_telemetry_collector):
        def _get_mock_thread():
            thread = MagicMock()
            thread.run = MagicMock()
            return thread

        all_threads = [mock_telemetry_send_events, mock_telemetry_collector, mock_env, mock_monitor, mock_collect_logs]

        for thread in all_threads:
            thread.return_value = _get_mock_thread()

        self._test_run(invocations=0)

        for thread in all_threads:
            self.assertEqual(1, thread.call_count)
            self.assertEqual(1, thread().run.call_count)

    def test_check_if_monitor_thread_is_alive(self, _, mock_monitor, *args):  # pylint: disable=unused-argument
        mock_monitor_thread = self._setup_mock_thread_and_start_test_run(mock_monitor, is_alive=True, invocations=1)
        self.assertEqual(1, mock_monitor.call_count)
        self.assertEqual(1, mock_monitor_thread.run.call_count)
        self.assertEqual(1, mock_monitor_thread.is_alive.call_count)
        self.assertEqual(0, mock_monitor_thread.start.call_count)

    def test_check_if_env_thread_is_alive(self, mock_env, *args):  # pylint: disable=unused-argument
        mock_env_thread = self._setup_mock_thread_and_start_test_run(mock_env, is_alive=True, invocations=1)
        self.assertEqual(1, mock_env.call_count)
        self.assertEqual(1, mock_env_thread.run.call_count)
        self.assertEqual(1, mock_env_thread.is_alive.call_count)
        self.assertEqual(0, mock_env_thread.start.call_count)

    def test_restart_monitor_thread_if_not_alive(self, _, mock_monitor, *args):  # pylint: disable=unused-argument
        mock_monitor_thread = self._setup_mock_thread_and_start_test_run(mock_monitor, is_alive=False, invocations=1)
        self.assertEqual(1, mock_monitor.call_count)
        self.assertEqual(1, mock_monitor_thread.run.call_count)
        self.assertEqual(1, mock_monitor_thread.is_alive.call_count)
        self.assertEqual(1, mock_monitor_thread.start.call_count)

    def test_restart_env_thread_if_not_alive(self, mock_env, *args):  # pylint: disable=unused-argument
        mock_env_thread = self._setup_mock_thread_and_start_test_run(mock_env, is_alive=False, invocations=1)
        self.assertEqual(1, mock_env.call_count)
        self.assertEqual(1, mock_env_thread.run.call_count)
        self.assertEqual(1, mock_env_thread.is_alive.call_count)
        self.assertEqual(1, mock_env_thread.start.call_count)

    def test_restart_monitor_thread(self, _, mock_monitor, *args):  # pylint: disable=unused-argument
        mock_monitor_thread = self._setup_mock_thread_and_start_test_run(mock_monitor, is_alive=False, invocations=1)
        self.assertEqual(True, mock_monitor.called)
        self.assertEqual(True, mock_monitor_thread.run.called)
        self.assertEqual(True, mock_monitor_thread.is_alive.called)
        self.assertEqual(True, mock_monitor_thread.start.called)

    def test_restart_env_thread(self, mock_env, *args):  # pylint: disable=unused-argument
        mock_env_thread = self._setup_mock_thread_and_start_test_run(mock_env, is_alive=False, invocations=1)
        self.assertEqual(True, mock_env.called)
        self.assertEqual(True, mock_env_thread.run.called)
        self.assertEqual(True, mock_env_thread.is_alive.called)
        self.assertEqual(True, mock_env_thread.start.called)


class ChildMock(Mock):
    def __init__(self, return_value=0, side_effect=None):
        Mock.__init__(self, return_value=return_value, side_effect=side_effect)

        self.poll = Mock(return_value=return_value, side_effect=side_effect)
        self.wait = Mock(return_value=return_value, side_effect=side_effect)


class GoalStateMock(object):
    def __init__(self, incarnation, family, versions):
        if versions is None:
            versions = []

        self.incarnation = incarnation
        self.extensions_goal_state = Mock()
        self.extensions_goal_state.id = incarnation
        self.extensions_goal_state.agent_families = GoalStateMock._create_agent_families(family, versions)

        agent_manifest = Mock()
        agent_manifest.pkg_list = GoalStateMock._create_packages(versions)
        self.fetch_agent_manifest = Mock(return_value=agent_manifest)

    @staticmethod
    def _create_agent_families(family, versions):
        families = []

        if len(versions) > 0 and family is not None:
            manifest = VMAgentFamily(name=family)
            for i in range(0, 10):
                manifest.uris.append("https://nowhere.msft/agent/{0}".format(i))
            families.append(manifest)

        return families

    @staticmethod
    def _create_packages(versions):
        packages = ExtHandlerPackageList()
        for version in versions:
            package = ExtHandlerPackage(str(version))
            for i in range(0, 5):
                package_uri = "https://nowhere.msft/agent_pkg/{0}".format(i)
                package.uris.append(package_uri)
            packages.versions.append(package)
        return packages


class ProtocolMock(object):
    def __init__(self, family="TestAgent", etag=42, versions=None, client=None):
        self.family = family
        self.client = client
        self.call_counts = {
            "update_goal_state": 0
        }
        self._goal_state = GoalStateMock(etag, family, versions)
        self.goal_state_is_stale = False
        self.etag = etag
        self.versions = versions if versions is not None else []

    def emulate_stale_goal_state(self):
        self.goal_state_is_stale = True

    def get_protocol(self):
        return self

    def get_goal_state(self):
        return self._goal_state

    def update_goal_state(self):
        self.call_counts["update_goal_state"] += 1


class TimeMock(Mock):
    def __init__(self, time_increment=1):
        Mock.__init__(self)
        self.next_time = time.time()
        self.time_call_count = 0
        self.time_increment = time_increment

        self.sleep_interval = None

    def sleep(self, n):
        self.sleep_interval = n

    def time(self):
        self.time_call_count += 1
        current_time = self.next_time
        self.next_time += self.time_increment
        return current_time


class TryUpdateGoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    """
    Tests for UpdateHandler._try_update_goal_state()
    """
    def test_it_should_return_true_on_success(self):
        update_handler = get_update_handler()
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            self.assertTrue(update_handler._try_update_goal_state(protocol), "try_update_goal_state should have succeeded")

    def test_it_should_return_false_on_failure(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            def http_get_handler(url, *_, **__):
                if self.is_goal_state_request(url):
                    return HttpError('Exception to fake an error retrieving the goal state')
                return None
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            update_handler = get_update_handler()
            self.assertFalse(update_handler._try_update_goal_state(protocol), "try_update_goal_state should have failed")

    def test_it_should_update_the_goal_state(self):
        update_handler = get_update_handler()
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            protocol.mock_wire_data.set_incarnation(12345)

            # the first goal state should produce an update
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(update_handler._goal_state.incarnation, '12345', "The goal state was not updated (received unexpected incarnation)")

            # no changes in the goal state should not produce an update
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(update_handler._goal_state.incarnation, '12345', "The goal state should not be updated (received unexpected incarnation)")

            # a new  goal state should produce an update
            protocol.mock_wire_data.set_incarnation(6789)
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(update_handler._goal_state.incarnation, '6789', "The goal state was not updated (received unexpected incarnation)")

    def test_it_should_log_errors_only_when_the_error_state_changes(self):
        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as protocol:
            def http_get_handler(url, *_, **__):
                if self.is_goal_state_request(url):
                    if fail_goal_state_request:
                        return HttpError('Exception to fake an error retrieving the goal state')
                return None

            protocol.set_http_handlers(http_get_handler=http_get_handler)

            @contextlib.contextmanager
            def create_log_and_telemetry_mocks():
                with patch("azurelinuxagent.ga.update.logger", autospec=True) as logger_patcher:
                    with patch("azurelinuxagent.ga.update.add_event") as add_event_patcher:
                        yield logger_patcher, add_event_patcher

            calls_to_strings = lambda calls: (str(c) for c in calls)
            filter_calls = lambda calls, regex=None: (c for c in calls_to_strings(calls) if regex is None or re.match(regex, c))
            logger_calls = lambda regex=None: [m for m in filter_calls(logger.method_calls, regex)]  # pylint: disable=used-before-assignment,unnecessary-comprehension
            errors = lambda: logger_calls(r'call.error\(.*Error fetching the goal state.*')
            periodic_errors = lambda: logger_calls(r'call.error\(.*Fetching the goal state is still failing*')
            success_messages = lambda: logger_calls(r'call.info\(.*Fetching the goal state recovered from previous errors.*')
            telemetry_calls = lambda regex=None: [m for m in filter_calls(add_event.mock_calls, regex)]  # pylint: disable=used-before-assignment,unnecessary-comprehension
            goal_state_events = lambda: telemetry_calls(r".*op='FetchGoalState'.*")

            #
            # Initially calls to retrieve the goal state are successful...
            #
            update_handler = get_update_handler()
            fail_goal_state_request = False
            with create_log_and_telemetry_mocks() as (logger, add_event):
                update_handler._try_update_goal_state(protocol)

                lc = logger_calls()
                self.assertTrue(len(lc) == 0, "A successful call should not produce any log messages: [{0}]".format(lc))

                tc = telemetry_calls()
                self.assertTrue(len(tc) == 0, "A successful call should not produce any telemetry events: [{0}]".format(tc))

            #
            # ... then an error happens...
            #
            fail_goal_state_request = True
            with create_log_and_telemetry_mocks() as (logger, add_event):
                update_handler._try_update_goal_state(protocol)

                e = errors()
                self.assertEqual(1, len(e), "A failure should have produced an error: [{0}]".format(e))

                gs = goal_state_events()
                self.assertTrue(len(gs) == 1 and 'is_success=False' in gs[0], "A failure should produce a telemetry event (success=false): [{0}]".format(gs))

            #
            # ... and errors continue happening...
            #
            with create_log_and_telemetry_mocks() as (logger, add_event):
                for _ in range(5):
                    update_handler._update_goal_state_last_error_report = datetime.now() + timedelta(days=1)
                    update_handler._try_update_goal_state(protocol)

                e = errors()
                pe = periodic_errors()
                self.assertEqual(2, len(e), "Two additional errors should have been reported: [{0}]".format(e))
                self.assertEqual(len(pe), 3, "Subsequent failures should produce periodic errors: [{0}]".format(pe))

                tc = telemetry_calls()
                self.assertTrue(len(tc) == 5, "The failures should have produced telemetry events. Got: [{0}]".format(tc))

            #
            # ... until we finally succeed
            #
            fail_goal_state_request = False
            with create_log_and_telemetry_mocks() as (logger, add_event):
                update_handler._try_update_goal_state(protocol)

                s = success_messages()
                e = errors()
                pe = periodic_errors()
                self.assertEqual(len(s), 1, "Recovering after failures should have produced an info message: [{0}]".format(s))
                self.assertTrue(len(e) == 0 and len(pe) == 0, "Recovering after failures should have not produced any errors: [{0}] [{1}]".format(e, pe))

                gs = goal_state_events()
                self.assertTrue(len(gs) == 1 and 'is_success=True' in gs[0], "Recovering after failures should produce a telemetry event (success=true): [{0}]".format(gs))


def _create_update_handler():
    """
    Creates an UpdateHandler in which agent updates are mocked as a no-op.
    """
    update_handler = get_update_handler()
    update_handler._download_agent_if_upgrade_available = Mock(return_value=False)
    return update_handler


@contextlib.contextmanager
def _mock_exthandlers_handler(extension_statuses=None):
    """
    Creates an ExtHandlersHandler that doesn't actually handle any extensions, but that returns status for 1 extension.
    The returned ExtHandlersHandler uses a mock WireProtocol, and both the run() and report_ext_handlers_status() are
    mocked. The mock run() is a no-op. If a list of extension_statuses is given, successive calls to the mock
    report_ext_handlers_status() returns a single extension with each of the statuses in the list. If extension_statuses
    is omitted all calls to report_ext_handlers_status() return a single extension with a success status.
    """
    def create_vm_status(extension_status):
        vm_status = VMStatus(status="Ready", message="Ready")
        vm_status.vmAgent.extensionHandlers = [ExtHandlerStatus()]
        vm_status.vmAgent.extensionHandlers[0].extension_status = ExtensionStatus(name="TestExtension")
        vm_status.vmAgent.extensionHandlers[0].extension_status.status = extension_status
        return vm_status

    with mock_wire_protocol(DATA_FILE) as protocol:
        exthandlers_handler = ExtHandlersHandler(protocol)
        exthandlers_handler.run = Mock()
        if extension_statuses is None:
            exthandlers_handler.report_ext_handlers_status = Mock(return_value=create_vm_status(ExtensionStatusValue.success))
        else:
            exthandlers_handler.report_ext_handlers_status = Mock(side_effect=[create_vm_status(s) for s in extension_statuses])
        exthandlers_handler.get_ext_handlers_status_debug_info = Mock(return_value='')
        yield exthandlers_handler


class ProcessGoalStateTestCase(AgentTestCase):
    """
    Tests for UpdateHandler._process_goal_state()
    """
    def test_it_should_process_goal_state_only_on_new_goal_state(self):
        with _mock_exthandlers_handler() as exthandlers_handler:
            update_handler = _create_update_handler()
            remote_access_handler = Mock()
            remote_access_handler.run = Mock()
            agent_update_handler = Mock()
            agent_update_handler.run = Mock()

            # process a goal state
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
            self.assertEqual(1, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have been called on the first goal state")
            self.assertEqual(1, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on the first goal state")
            self.assertEqual(1, remote_access_handler.run.call_count, "remote_access_handler.run() should have been called on the first goal state")
            self.assertEqual(1, agent_update_handler.run.call_count, "agent_update_handler.run() should have been called on the first goal state")

            # process the same goal state
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
            self.assertEqual(1, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have not been called on the same goal state")
            self.assertEqual(2, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on the same goal state")
            self.assertEqual(1, remote_access_handler.run.call_count, "remote_access_handler.run() should not have been called on the same goal state")
            self.assertEqual(2, agent_update_handler.run.call_count, "agent_update_handler.run() should have been called on the same goal state")

            # process a new goal state
            exthandlers_handler.protocol.mock_wire_data.set_incarnation(999)
            exthandlers_handler.protocol.client.update_goal_state()
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
            self.assertEqual(2, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have been called on a new goal state")
            self.assertEqual(3, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on a new goal state")
            self.assertEqual(2, remote_access_handler.run.call_count, "remote_access_handler.run() should have been called on a new goal state")
            self.assertEqual(3, agent_update_handler.run.call_count, "agent_update_handler.run() should have been called on the new goal state")

    def test_it_should_write_the_agent_status_to_the_history_folder(self):
        with _mock_exthandlers_handler() as exthandlers_handler:
            update_handler = _create_update_handler()
            remote_access_handler = Mock()
            remote_access_handler.run = Mock()
            agent_update_handler = Mock()
            agent_update_handler.run = Mock()

            update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)

            incarnation = exthandlers_handler.protocol.get_goal_state().incarnation
            matches = glob.glob(os.path.join(conf.get_lib_dir(), ARCHIVE_DIRECTORY_NAME, "*_{0}".format(incarnation)))
            self.assertTrue(len(matches) == 1, "Could not find the history directory for the goal state. Got: {0}".format(matches))

            status_file = os.path.join(matches[0], AGENT_STATUS_FILE)
            self.assertTrue(os.path.exists(status_file), "Could not find {0}".format(status_file))

    @staticmethod
    def _prepare_fast_track_goal_state():
        """
        Creates a set of mock wire data where the most recent goal state is a FastTrack goal state; also
        invokes HostPluginProtocol.fetch_vm_settings() to save the Fast Track status to disk
        """
        # Do a query for the vmSettings; this would retrieve a FastTrack goal state and keep track of its timestamp
        mock_wire_data_file = wire_protocol_data.DATA_FILE_VM_SETTINGS.copy()
        with mock_wire_protocol(mock_wire_data_file) as protocol:
            protocol.mock_wire_data.set_etag("0123456789")
            _ = protocol.client.get_host_plugin().fetch_vm_settings()
        return mock_wire_data_file

    def test_it_should_mark_outdated_goal_states_on_service_restart_when_fast_track_is_disabled(self):
        data_file = self._prepare_fast_track_goal_state()

        with patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=False):
            with mock_wire_protocol(data_file) as protocol:
                with mock_update_handler(protocol) as update_handler:
                    update_handler.run()

                    self.assertTrue(protocol.client.get_goal_state().extensions_goal_state.is_outdated)

    @staticmethod
    def _http_get_vm_settings_handler_not_found(url, *_, **__):
        if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
            return MockHttpResponse(httpclient.NOT_FOUND)  # HostGAPlugin returns 404 if the API is not supported
        return None

    def test_it_should_mark_outdated_goal_states_on_service_restart_when_host_ga_plugin_stops_supporting_vm_settings(self):
        data_file = self._prepare_fast_track_goal_state()

        with mock_wire_protocol(data_file, http_get_handler=self._http_get_vm_settings_handler_not_found) as protocol:
            with mock_update_handler(protocol) as update_handler:
                update_handler.run()

                self.assertTrue(protocol.client.get_goal_state().extensions_goal_state.is_outdated)

    def test_it_should_clear_the_timestamp_for_the_most_recent_fast_track_goal_state(self):
        data_file = self._prepare_fast_track_goal_state()

        if HostPluginProtocol.get_fast_track_timestamp() == timeutil.create_timestamp(datetime.min):
            raise Exception("The test setup did not save the Fast Track state")

        with patch("azurelinuxagent.common.conf.get_enable_fast_track", return_value=False):
            with patch("azurelinuxagent.common.version.get_daemon_version",
                       return_value=FlexibleVersion("2.2.53")):
                with mock_wire_protocol(data_file) as protocol:
                    with mock_update_handler(protocol) as update_handler:
                        update_handler.run()

        self.assertEqual(HostPluginProtocol.get_fast_track_timestamp(), timeutil.create_timestamp(datetime.min),
            "The Fast Track state was not cleared")

    def test_it_should_default_fast_track_timestamp_to_datetime_min(self):
        data = DATA_FILE_VM_SETTINGS.copy()
        # TODO: Currently, there's a limitation in the mocks where bumping the incarnation but the goal
        # state will cause the agent to error out while trying to write the certificates to disk. These
        # files have no dependencies on certs, so using them does not present that issue.
        #
        # Note that the scenario this test is representing does not depend on certificates at all, and
        # can be changed to use the default files when the above limitation is addressed.
        data["vm_settings"] = "hostgaplugin/vm_settings-fabric-no_thumbprints.json"
        data['goal_state'] = 'wire/goal_state_no_certs.xml'

        def vm_settings_no_change(url, *_, **__):
            if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
                return MockHttpResponse(httpclient.NOT_MODIFIED)
            return None

        def vm_settings_not_supported(url, *_, **__):
            if HttpRequestPredicates.is_host_plugin_vm_settings_request(url):
                return MockHttpResponse(404)
            return None

        with mock_wire_protocol(data) as protocol:

            def mock_live_migration(iteration):
                if iteration == 1:
                    protocol.mock_wire_data.set_incarnation(2)
                    protocol.set_http_handlers(http_get_handler=vm_settings_no_change)
                elif iteration == 2:
                    protocol.mock_wire_data.set_incarnation(3)
                    protocol.set_http_handlers(http_get_handler=vm_settings_not_supported)

            with mock_update_handler(protocol, 3, on_new_iteration=mock_live_migration) as update_handler:
                with patch("azurelinuxagent.ga.update.logger.error") as patched_error:
                    def check_for_errors():
                        msg_fragment = "Error fetching the goal state:"

                        for (args, _) in filter(lambda a: len(a) > 0, patched_error.call_args_list):
                            if msg_fragment in args[0]:
                                self.fail("Found error: {}".format(args[0]))

                    update_handler.run(debug=True)
                    check_for_errors()

            timestamp = protocol.client.get_host_plugin()._fast_track_timestamp
            self.assertEqual(timestamp, timeutil.create_timestamp(datetime.min),
                "Expected fast track time stamp to be set to {0}, got {1}".format(datetime.min, timestamp))

class HeartbeatTestCase(AgentTestCase):

    @patch("azurelinuxagent.common.logger.info")
    @patch("azurelinuxagent.ga.update.add_event")
    def test_telemetry_heartbeat_creates_event(self, patch_add_event, patch_info, *_):

        with mock_wire_protocol(wire_protocol_data.DATA_FILE) as mock_protocol:
            update_handler = get_update_handler()

            update_handler.last_telemetry_heartbeat = datetime.utcnow() - timedelta(hours=1)
            update_handler._send_heartbeat_telemetry(mock_protocol)
            self.assertEqual(1, patch_add_event.call_count)
            self.assertTrue(any(call_args[0] == "[HEARTBEAT] Agent {0} is running as the goal state agent {1}"
                            for call_args in patch_info.call_args), "The heartbeat was not written to the agent's log")


class AgentMemoryCheckTestCase(AgentTestCase):

    @patch("azurelinuxagent.common.logger.info")
    @patch("azurelinuxagent.ga.update.add_event")
    def test_check_agent_memory_usage_raises_exit_exception(self, patch_add_event, patch_info, *_):
        with patch("azurelinuxagent.ga.cgroupconfigurator.CGroupConfigurator._Impl.check_agent_memory_usage", side_effect=AgentMemoryExceededException()):
            with patch('azurelinuxagent.common.conf.get_enable_agent_memory_usage_check', return_value=True):
                with self.assertRaises(ExitException) as context_manager:
                    update_handler = get_update_handler()

                    update_handler._check_agent_memory_usage()
                    self.assertEqual(1, patch_add_event.call_count)
                    self.assertTrue(any("Check on agent memory usage" in call_args[0]
                                        for call_args in patch_info.call_args),
                                    "The memory check was not written to the agent's log")
                    self.assertIn("Agent {0} is reached memory limit -- exiting".format(CURRENT_AGENT),
                                  ustr(context_manager.exception), "An incorrect exception was raised")

    @patch("azurelinuxagent.common.logger.warn")
    @patch("azurelinuxagent.ga.update.add_event")
    def test_check_agent_memory_usage_fails(self, patch_add_event, patch_warn, *_):
        with patch("azurelinuxagent.ga.cgroupconfigurator.CGroupConfigurator._Impl.check_agent_memory_usage", side_effect=Exception()):
            with patch('azurelinuxagent.common.conf.get_enable_agent_memory_usage_check', return_value=True):
                update_handler = get_update_handler()

                update_handler._check_agent_memory_usage()
                self.assertTrue(any("Error checking the agent's memory usage" in call_args[0]
                                    for call_args in patch_warn.call_args),
                                "The memory check was not written to the agent's log")
                self.assertEqual(1, patch_add_event.call_count)
                add_events = [kwargs for _, kwargs in patch_add_event.call_args_list if
                                kwargs["op"] == WALAEventOperation.AgentMemory]
                self.assertTrue(
                    len(add_events) == 1,
                    "Exactly 1 event should have been emitted when memory usage check fails. Got: {0}".format(add_events))
                self.assertIn(
                    "Error checking the agent's memory usage",
                    add_events[0]["message"],
                    "The error message is not correct when memory usage check failed")


class GoalStateIntervalTestCase(AgentTestCase):
    def test_initial_goal_state_period_should_default_to_goal_state_period(self):
        configuration_provider = conf.ConfigurationProvider()
        test_file = os.path.join(self.tmp_dir, "waagent.conf")
        with open(test_file, "w") as file_:
            file_.write("Extensions.GoalStatePeriod=987654321\n")
        conf.load_conf_from_file(test_file, configuration_provider)

        self.assertEqual(987654321, conf.get_initial_goal_state_period(conf=configuration_provider))

    def test_update_handler_should_use_the_default_goal_state_period(self):
        update_handler = get_update_handler()
        default = conf.get_int_default_value("Extensions.GoalStatePeriod")
        self.assertEqual(default, update_handler._goal_state_period, "The UpdateHanlder is not using the default goal state period")

    def test_update_handler_should_not_use_the_default_goal_state_period_when_extensions_are_disabled(self):
        with patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False):
            update_handler = get_update_handler()
            self.assertEqual(GOAL_STATE_PERIOD_EXTENSIONS_DISABLED, update_handler._goal_state_period, "Incorrect goal state period when extensions are disabled")

    def test_the_default_goal_state_period_and_initial_goal_state_period_should_be_the_same(self):
        update_handler = get_update_handler()
        default = conf.get_int_default_value("Extensions.GoalStatePeriod")
        self.assertEqual(default, update_handler._goal_state_period, "The UpdateHanlder is not using the default goal state period")

    def test_update_handler_should_use_the_initial_goal_state_period_when_it_is_different_to_the_goal_state_period(self):
        with patch('azurelinuxagent.common.conf.get_initial_goal_state_period', return_value=99999):
            update_handler = get_update_handler()
            self.assertEqual(99999, update_handler._goal_state_period, "Expected the initial goal state period")

    def test_update_handler_should_use_the_initial_goal_state_period_until_the_goal_state_converges(self):
        initial_goal_state_period, goal_state_period = 11111, 22222
        with patch('azurelinuxagent.common.conf.get_initial_goal_state_period', return_value=initial_goal_state_period):
            with patch('azurelinuxagent.common.conf.get_goal_state_period', return_value=goal_state_period):
                with _mock_exthandlers_handler([ExtensionStatusValue.transitioning, ExtensionStatusValue.success]) as exthandlers_handler:
                    remote_access_handler = Mock()
                    agent_update_handler = Mock()

                    update_handler = _create_update_handler()
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period")

                    # the extension is transisioning, so we should still be using the initial goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period when the extension is transitioning")

                    # the goal state converged (the extension succeeded), so we should switch to the regular goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
                    self.assertEqual(goal_state_period, update_handler._goal_state_period, "Expected the regular goal state period after the goal state converged")

    def test_update_handler_should_switch_to_the_regular_goal_state_period_when_the_goal_state_does_not_converges(self):
        initial_goal_state_period, goal_state_period = 11111, 22222
        with patch('azurelinuxagent.common.conf.get_initial_goal_state_period', return_value=initial_goal_state_period):
            with patch('azurelinuxagent.common.conf.get_goal_state_period', return_value=goal_state_period):
                with _mock_exthandlers_handler([ExtensionStatusValue.transitioning, ExtensionStatusValue.transitioning]) as exthandlers_handler:
                    remote_access_handler = Mock()
                    agent_update_handler = Mock()

                    update_handler = _create_update_handler()
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period")

                    # the extension is transisioning, so we should still be using the initial goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period when the extension is transitioning")

                    # a new goal state arrives before the current goal state converged (the extension is transitioning), so we should switch to the regular goal state period
                    exthandlers_handler.protocol.mock_wire_data.set_incarnation(100)
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler, agent_update_handler)
                    self.assertEqual(goal_state_period, update_handler._goal_state_period, "Expected the regular goal state period when the goal state does not converge")


class ExtensionsSummaryTestCase(AgentTestCase):
    @staticmethod
    def _create_extensions_summary(extension_statuses):
        """
        Creates an ExtensionsSummary from an array of (extension name, extension status) tuples
        """
        vm_status = VMStatus(status="Ready", message="Ready")
        vm_status.vmAgent.extensionHandlers = [ExtHandlerStatus()] * len(extension_statuses)
        for i in range(len(extension_statuses)):
            vm_status.vmAgent.extensionHandlers[i].extension_status = ExtensionStatus(name=extension_statuses[i][0])
            vm_status.vmAgent.extensionHandlers[0].extension_status.status = extension_statuses[i][1]
        return ExtensionsSummary(vm_status)

    def test_equality_operator_should_return_true_on_items_with_the_same_value(self):
        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])

        self.assertTrue(summary1 == summary2, "{0} == {1} should be True".format(summary1, summary2))

    def test_equality_operator_should_return_false_on_items_with_different_values(self):
        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.success)])

        self.assertFalse(summary1 == summary2, "{0} == {1} should be False")

        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.success)])

        self.assertFalse(summary1 == summary2, "{0} == {1} should be False")

    def test_inequality_operator_should_return_true_on_items_with_different_values(self):
        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.success)])

        self.assertTrue(summary1 != summary2, "{0} != {1} should be True".format(summary1, summary2))

        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.success)])

        self.assertTrue(summary1 != summary2, "{0} != {1} should be True")

    def test_inequality_operator_should_return_false_on_items_with_same_value(self):
        summary1 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])
        summary2 = ExtensionsSummaryTestCase._create_extensions_summary([("Extension 1", ExtensionStatusValue.success), ("Extension 2", ExtensionStatusValue.transitioning)])

        self.assertFalse(summary1 != summary2, "{0} != {1} should be False".format(summary1, summary2))


if __name__ == '__main__':
    unittest.main()
