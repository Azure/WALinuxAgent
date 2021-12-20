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
import zipfile

from datetime import datetime, timedelta
from threading import currentThread
from tests.common.osutil.test_default import TestOSUtil
import azurelinuxagent.common.osutil.default as osutil

_ORIGINAL_POPEN = subprocess.Popen

from mock import PropertyMock

from azurelinuxagent.common import conf
from azurelinuxagent.common.event import EVENTS_DIRECTORY, WALAEventOperation
from azurelinuxagent.common.exception import ProtocolError, UpdateError, ResourceGoneError, HttpError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.persist_firewall_rules import PersistFirewallRulesHandler
from azurelinuxagent.common.protocol.hostplugin import URI_FORMAT_GET_API_VERSIONS, HOST_PLUGIN_PORT, \
    URI_FORMAT_GET_EXTENSION_ARTIFACT, HostPluginProtocol
from azurelinuxagent.common.protocol.restapi import VMAgentManifest, \
    ExtHandlerPackage, ExtHandlerPackageList, Extension, VMStatus, ExtHandlerStatus, ExtensionStatus, \
    VMAgentUpdateStatuses
from azurelinuxagent.common.protocol.util import ProtocolUtil
from azurelinuxagent.common.protocol.wire import WireProtocol
from azurelinuxagent.common.utils import fileutil, restutil, textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.utils.networkutil import FirewallCmdDirectCommands, AddFirewallRules
from azurelinuxagent.common.version import AGENT_PKG_GLOB, AGENT_DIR_GLOB, AGENT_NAME, AGENT_DIR_PATTERN, \
    AGENT_VERSION, CURRENT_AGENT, CURRENT_VERSION
from azurelinuxagent.ga.exthandlers import ExtHandlersHandler, ExtHandlerInstance, HandlerEnvironment, ExtensionStatusValue
from azurelinuxagent.ga.update import GuestAgent, GuestAgentError, MAX_FAILURE, AGENT_MANIFEST_FILE, \
    get_update_handler, ORPHAN_POLL_INTERVAL, AGENT_PARTITION_FILE, AGENT_ERROR_FILE, ORPHAN_WAIT_INTERVAL, \
    CHILD_LAUNCH_RESTART_MAX, CHILD_HEALTH_INTERVAL, GOAL_STATE_PERIOD_EXTENSIONS_DISABLED, UpdateHandler, \
    READONLY_FILE_GLOBS, ExtensionsSummary, AgentUpgradeType
from tests.protocol.mocks import mock_wire_protocol, MockHttpResponse
from tests.protocol.mockwiredata import DATA_FILE, DATA_FILE_MULTIPLE_EXT
from tests.tools import AgentTestCase, data_dir, DEFAULT, patch, load_bin_data, Mock, MagicMock, \
    clear_singleton_instances, mock_sleep, skip_if_predicate_true
from tests.protocol import mockwiredata
from tests.protocol.HttpRequestPredicates import HttpRequestPredicates

NO_ERROR = {
    "last_failure": 0.0,
    "failure_count": 0,
    "was_fatal": False
}

FATAL_ERROR = {
    "last_failure": 42.42,
    "failure_count": 2,
    "was_fatal": True
}

WITH_ERROR = {
    "last_failure": 42.42,
    "failure_count": 2,
    "was_fatal": False
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
def _get_update_handler(iterations=1, test_data=None):
    """
    This function returns a mocked version of the UpdateHandler object to be used for testing. It will only run the
    main loop [iterations] no of times.
    To reuse the same object, be sure to reset the iterations by using the update_handler.set_iterations() function.
    :param iterations: No of times the UpdateHandler.run() method should run.
    :return: Mocked object of UpdateHandler() class and object of the MockWireProtocol().
    """

    def _set_iterations(iterations_):
        # This will reset the current iteration and the max iterations to run for this test object.
        update_handler._cur_iteration = 0
        update_handler._iterations = iterations_

    def check_running(*val, **__):
        # This method will determine if the current UpdateHandler object is supposed to run or not.

        # There can be scenarios where the UpdateHandler.is_running.setter is called, in that case, return the first
        # value of the tuple and not increment the cur_iteration
        if len(val) > 0:
            return val[0]

        if update_handler._cur_iteration < update_handler._iterations:
            update_handler._cur_iteration += 1
            return True
        return False

    test_data = DATA_FILE if test_data is None else test_data

    with mock_wire_protocol(test_data) as protocol:
        protocol_util = MagicMock()
        protocol_util.get_protocol = Mock(return_value=protocol)
        with patch("azurelinuxagent.ga.update.get_protocol_util", return_value=protocol_util):
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=False):
                with patch.object(HostPluginProtocol, "is_default_channel", False):
                    update_handler = get_update_handler()
                    # Setup internal state for the object required for testing
                    update_handler._cur_iteration = 0
                    update_handler._iterations = 0
                    update_handler.set_iterations = _set_iterations
                    update_handler.get_iterations = lambda: update_handler._cur_iteration
                    type(update_handler).is_running = PropertyMock(side_effect=check_running)
                    with patch("time.sleep", side_effect=lambda _: mock_sleep(0.001)):
                        with patch('sys.exit') as exit_mock:
                            # Setup the initial number of iterations
                            update_handler.set_iterations(iterations)
                            update_handler.exit_mock = exit_mock
                            try:
                                yield update_handler, protocol
                            finally:
                                # Since PropertyMock requires us to mock the type(ClassName).property of the object,
                                # reverting it back to keep the state of the test clean
                                type(update_handler).is_running = True


class UpdateTestCase(AgentTestCase):
    _test_suite_tmp_dir = None
    _agent_zip_dir = None

    @classmethod
    def setUpClass(cls):
        AgentTestCase.setUpClass()
        # copy data_dir/ga/WALinuxAgent-0.0.0.0.zip to _test_suite_tmp_dir/waagent-zip/WALinuxAgent-<AGENT_VERSION>.zip
        sample_agent_zip = "WALinuxAgent-0.0.0.0.zip"
        test_agent_zip = sample_agent_zip.replace("0.0.0.0", AGENT_VERSION)
        UpdateTestCase._test_suite_tmp_dir = tempfile.mkdtemp()
        UpdateTestCase._agent_zip_dir = os.path.join(UpdateTestCase._test_suite_tmp_dir, "waagent-zip")
        os.mkdir(UpdateTestCase._agent_zip_dir)
        source = os.path.join(data_dir, "ga", sample_agent_zip)
        target = os.path.join(UpdateTestCase._agent_zip_dir, test_agent_zip)
        shutil.copyfile(source, target)

    @classmethod
    def tearDownClass(cls):
        AgentTestCase.tearDownClass()
        shutil.rmtree(UpdateTestCase._test_suite_tmp_dir)

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
        return [GuestAgent(path=path) for path in self.agent_dirs()]

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
                GuestAgent(to_path).mark_failure(is_fatal=True)
        return dst_v


class TestGuestAgentError(UpdateTestCase):
    def test_creation(self):
        self.assertRaises(TypeError, GuestAgentError)
        self.assertRaises(UpdateError, GuestAgentError, None)

        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            err.load()
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        self.assertEqual(WITH_ERROR["last_failure"], err.last_failure)
        self.assertEqual(WITH_ERROR["failure_count"], err.failure_count)
        self.assertEqual(WITH_ERROR["was_fatal"], err.was_fatal)
        return

    def test_clear(self):
        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            err.load()
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        err.clear()
        self.assertEqual(NO_ERROR["last_failure"], err.last_failure)
        self.assertEqual(NO_ERROR["failure_count"], err.failure_count)
        self.assertEqual(NO_ERROR["was_fatal"], err.was_fatal)
        return

    def test_save(self):
        err1 = self.create_error()
        err1.mark_failure()
        err1.mark_failure(is_fatal=True)

        err2 = self.create_error(err1.to_json())
        self.assertEqual(err1.last_failure, err2.last_failure)
        self.assertEqual(err1.failure_count, err2.failure_count)
        self.assertEqual(err1.was_fatal, err2.was_fatal)

    def test_mark_failure(self):
        err = self.create_error()
        self.assertFalse(err.is_blacklisted)

        for i in range(0, MAX_FAILURE):  # pylint: disable=unused-variable
            err.mark_failure()

        # Agent failed >= MAX_FAILURE, it should be blacklisted
        self.assertTrue(err.is_blacklisted)
        self.assertEqual(MAX_FAILURE, err.failure_count)
        return

    def test_mark_failure_permanent(self):
        err = self.create_error()

        self.assertFalse(err.is_blacklisted)

        # Fatal errors immediately blacklist
        err.mark_failure(is_fatal=True)
        self.assertTrue(err.is_blacklisted)
        self.assertTrue(err.failure_count < MAX_FAILURE)
        return

    def test_str(self):
        err = self.create_error(error_data=NO_ERROR)
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}".format(
            NO_ERROR["last_failure"],
            NO_ERROR["failure_count"],
            NO_ERROR["was_fatal"])
        self.assertEqual(s, str(err))

        err = self.create_error(error_data=WITH_ERROR)
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}".format(
            WITH_ERROR["last_failure"],
            WITH_ERROR["failure_count"],
            WITH_ERROR["was_fatal"])
        self.assertEqual(s, str(err))
        return


class TestGuestAgent(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.copy_agents(self._get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, self._get_agent_name())

    def test_creation(self):
        self.assertRaises(UpdateError, GuestAgent, "A very bad file name")
        n = "{0}-a.bad.version".format(AGENT_NAME)
        self.assertRaises(UpdateError, GuestAgent, n)

        self.expand_agents()

        agent = GuestAgent(path=self.agent_path)
        self.assertNotEqual(None, agent)
        self.assertEqual(self._get_agent_name(), agent.name)
        self.assertEqual(self._get_agent_version(), agent.version)

        self.assertEqual(self.agent_path, agent.get_agent_dir())

        path = os.path.join(self.agent_path, AGENT_MANIFEST_FILE)
        self.assertEqual(path, agent.get_agent_manifest_path())

        self.assertEqual(
            os.path.join(self.agent_path, AGENT_ERROR_FILE),
            agent.get_agent_error_file())

        path = ".".join((os.path.join(conf.get_lib_dir(), self._get_agent_name()), "zip"))
        self.assertEqual(path, agent.get_agent_pkg_path())

        self.assertTrue(agent.is_downloaded)
        self.assertFalse(agent.is_blacklisted)
        self.assertTrue(agent.is_available)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_clear_error(self, mock_downloaded):  # pylint: disable=unused-argument
        self.expand_agents()

        agent = GuestAgent(path=self.agent_path)
        agent.mark_failure(is_fatal=True)

        self.assertTrue(agent.error.last_failure > 0.0)
        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

        agent.clear_error()
        self.assertEqual(0.0, agent.error.last_failure)
        self.assertEqual(0, agent.error.failure_count)
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_is_available(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)

        self.assertFalse(agent.is_available)
        agent._unpack()
        self.assertTrue(agent.is_available)

        agent.mark_failure(is_fatal=True)
        self.assertFalse(agent.is_available)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_is_blacklisted(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(agent.is_blacklisted)

        agent._unpack()
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_resource_gone_error_not_blacklisted(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        try:
            mock_downloaded.side_effect = ResourceGoneError()
            agent = GuestAgent(path=self.agent_path)
            self.assertFalse(agent.is_blacklisted)
        except ResourceGoneError:
            pass
        except:  # pylint: disable=bare-except
            self.fail("Exception was not expected!")

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_ioerror_not_blacklisted(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        try:
            mock_downloaded.side_effect = IOError()
            agent = GuestAgent(path=self.agent_path)
            self.assertFalse(agent.is_blacklisted)
        except IOError:
            pass
        except:  # pylint: disable=bare-except
            self.fail("Exception was not expected!")

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_is_downloaded(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(agent.is_downloaded)
        agent._unpack()
        self.assertTrue(agent.is_downloaded)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_mark_failure(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)

        agent.mark_failure()
        self.assertEqual(1, agent.error.failure_count)

        agent.mark_failure(is_fatal=True)
        self.assertEqual(2, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_unpack(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isdir(agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_unpack_fail(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        os.remove(agent.get_agent_pkg_path())
        self.assertRaises(UpdateError, agent._unpack)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        agent._unpack()
        agent._load_manifest()
        self.assertEqual(agent.manifest.get_enable_command(),
                         agent.get_agent_cmd())

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_missing(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        os.remove(agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, agent._load_manifest)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_is_empty(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, agent._load_manifest)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_is_malformed(self, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            file.write("This is not JSON data")
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_error(self):
        agent = GuestAgent(path=self.agent_path)
        agent.error = None

        agent._load_error()
        self.assertTrue(agent.error is not None)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download(self, mock_http_get, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
        mock_http_get.return_value = ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)
        agent._download()

        self.assertTrue(os.path.isfile(agent.get_agent_pkg_path()))

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download_fail(self, mock_http_get, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        mock_http_get.return_value = ResponseMock(status=restutil.httpclient.SERVICE_UNAVAILABLE)

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertRaises(UpdateError, agent._download)
        self.assertFalse(os.path.isfile(agent.get_agent_pkg_path()))
        self.assertFalse(agent.is_downloaded)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    @patch("azurelinuxagent.ga.update.restutil.http_post")
    def test_download_fallback(self, mock_http_post, mock_http_get, mock_loaded, mock_downloaded):  # pylint: disable=unused-argument
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        mock_http_get.return_value = ResponseMock(
            status=restutil.httpclient.SERVICE_UNAVAILABLE,
            response="")

        ext_uri = 'ext_uri'
        host_uri = 'host_uri'
        api_uri = URI_FORMAT_GET_API_VERSIONS.format(host_uri, HOST_PLUGIN_PORT)
        art_uri = URI_FORMAT_GET_EXTENSION_ARTIFACT.format(host_uri, HOST_PLUGIN_PORT)
        mock_host = HostPluginProtocol(host_uri,
                                       'container_id',
                                       'role_config')

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(ext_uri)
        agent = GuestAgent(pkg=pkg)
        agent.host = mock_host

        # ensure fallback fails gracefully, no http
        self.assertRaises(UpdateError, agent._download)
        self.assertEqual(mock_http_get.call_count, 2)
        self.assertEqual(mock_http_get.call_args_list[0][0][0], ext_uri)
        self.assertEqual(mock_http_get.call_args_list[1][0][0], api_uri)

        # ensure fallback fails gracefully, artifact api failure
        with patch.object(HostPluginProtocol,
                          "ensure_initialized",
                          return_value=True):
            self.assertRaises(UpdateError, agent._download)
            self.assertEqual(mock_http_get.call_count, 4)

            self.assertEqual(mock_http_get.call_args_list[2][0][0], ext_uri)

            self.assertEqual(mock_http_get.call_args_list[3][0][0], art_uri)
            a, k = mock_http_get.call_args_list[3]  # pylint: disable=unused-variable
            self.assertEqual(False, k['use_proxy'])

            # ensure fallback works as expected
            with patch.object(HostPluginProtocol,
                              "get_artifact_request",
                              return_value=[art_uri, {}]):
                self.assertRaises(UpdateError, agent._download)
                self.assertEqual(mock_http_get.call_count, 6)

                a, k = mock_http_get.call_args_list[3]
                self.assertEqual(False, k['use_proxy'])

                self.assertEqual(mock_http_get.call_args_list[4][0][0], ext_uri)
                a, k = mock_http_get.call_args_list[4]

                self.assertEqual(mock_http_get.call_args_list[5][0][0], art_uri)
                a, k = mock_http_get.call_args_list[5]
                self.assertEqual(False, k['use_proxy'])

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_ensure_downloaded(self, mock_http_get):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
        mock_http_get.return_value = ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))
        self.assertTrue(agent.is_downloaded)

    @patch("azurelinuxagent.ga.update.GuestAgent._download", side_effect=UpdateError)
    def test_ensure_downloaded_download_fails(self, mock_download):  # pylint: disable=unused-argument
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertFalse(agent.error.was_fatal)
        self.assertFalse(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack", side_effect=UpdateError)
    def test_ensure_downloaded_unpack_fails(self, mock_unpack, mock_download):  # pylint: disable=unused-argument
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest", side_effect=UpdateError)
    def test_ensure_downloaded_load_manifest_fails(self, mock_manifest, mock_unpack, mock_download):  # pylint: disable=unused-argument
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest")
    def test_ensure_download_skips_blacklisted(self, mock_manifest, mock_unpack, mock_download):  # pylint: disable=unused-argument
        agent = GuestAgent(path=self.agent_path)
        self.assertEqual(0, mock_download.call_count)

        agent.clear_error()
        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)

        pkg = ExtHandlerPackage(version=str(self._get_agent_version()))
        pkg.uris.append(None)
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(0, mock_download.call_count)
        self.assertEqual(0, mock_unpack.call_count)


class TestUpdate(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.event_patch = patch('azurelinuxagent.common.event.add_event')
        self.update_handler = get_update_handler()
        protocol = Mock()
        self.update_handler.protocol_util = Mock()
        self.update_handler.protocol_util.get_protocol = Mock(return_value=protocol)

        # Since ProtocolUtil is a singleton per thread, we need to clear it to ensure that the test cases do not reuse
        # a previous state
        clear_singleton_instances(ProtocolUtil)

    def test_creation(self):
        self.assertEqual(None, self.update_handler.last_attempt_time)

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

        latest_agent = self.update_handler.get_latest_agent()
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

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])
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

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_host_plugin')
    def test_get_host_plugin_returns_host_for_wireserver(self, mock_get_host):
        protocol = WireProtocol('12.34.56.78')
        mock_get_host.return_value = "faux host"
        host = self.update_handler._get_host_plugin(protocol=protocol)
        print("mock_get_host call cound={0}".format(mock_get_host.call_count))
        self.assertEqual(1, mock_get_host.call_count)
        self.assertEqual("faux host", host)

    def test_get_latest_agent(self):
        latest_version = self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertEqual(len(self._get_agents(self.tmp_dir)), len(self.update_handler.agents))
        self.assertEqual(latest_version, latest_agent.version)

    def test_get_latest_agent_excluded(self):
        self.prepare_agent(AGENT_VERSION)
        self.assertFalse(self._test_upgrade_available(
            versions=self.agent_versions(),
            count=1))
        self.assertEqual(None, self.update_handler.get_latest_agent())

    def test_get_latest_agent_no_updates(self):
        self.assertEqual(None, self.update_handler.get_latest_agent())

    def test_get_latest_agent_skip_updates(self):
        conf.get_autoupdate_enabled = Mock(return_value=False)
        self.assertEqual(None, self.update_handler.get_latest_agent())

    def test_get_latest_agent_skips_unavailable(self):
        self.prepare_agents()
        prior_agent = self.update_handler.get_latest_agent()

        latest_version = self.prepare_agents(count=self.agent_count() + 1, is_available=False)
        latest_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, latest_version))
        self.assertFalse(GuestAgent(latest_path).is_available)

        latest_agent = self.update_handler.get_latest_agent()
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

    def test_is_version_available(self):
        self.prepare_agents(is_available=True)
        self.update_handler.agents = self.agents()

        for agent in self.agents():
            self.assertTrue(self.update_handler._is_version_eligible(agent.version))

    @patch("azurelinuxagent.ga.update.is_current_agent_installed", return_value=False)
    def test_is_version_available_rejects(self, mock_current):  # pylint: disable=unused-argument
        self.prepare_agents(is_available=True)
        self.update_handler.agents = self.agents()

        self.update_handler.agents[0].mark_failure(is_fatal=True)
        self.assertFalse(self.update_handler._is_version_eligible(self.agents()[0].version))

    @patch("azurelinuxagent.ga.update.is_current_agent_installed", return_value=True)
    def test_is_version_available_accepts_current(self, mock_current):  # pylint: disable=unused-argument
        self.update_handler.agents = []
        self.assertTrue(self.update_handler._is_version_eligible(CURRENT_VERSION))

    @patch("azurelinuxagent.ga.update.is_current_agent_installed", return_value=False)
    def test_is_version_available_rejects_by_default(self, mock_current):  # pylint: disable=unused-argument
        self.prepare_agents()
        self.update_handler.agents = []

        v = self.agents()[0].version
        self.assertFalse(self.update_handler._is_version_eligible(v))

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

        agent = self.update_handler.get_latest_agent()
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

        agent = self.update_handler.get_latest_agent()  # pylint: disable=unused-variable
        args, kwargs = self._test_run_latest(child_args="AnArgument")  # pylint: disable=unused-variable
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
        self.assertEqual(None, self.update_handler.get_latest_agent())

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

    def test_run_latest_nonzero_code_marks_failures(self):
        # logger.add_logger_appender(logger.AppenderType.STDOUT)
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent', return_value=latest_agent):
            self._test_run_latest(mock_child=ChildMock(return_value=1))

        self.assertTrue(latest_agent.is_blacklisted)
        self.assertFalse(latest_agent.is_available)
        self.assertNotEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)

    def test_run_latest_exception_blacklists(self):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent', return_value=latest_agent):
            self._test_run_latest(mock_child=ChildMock(side_effect=Exception("Force blacklisting")))

        self.assertFalse(latest_agent.is_available)
        self.assertTrue(latest_agent.error.is_blacklisted)
        self.assertNotEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)

    def test_run_latest_exception_does_not_blacklist_if_terminating(self):
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        with patch('azurelinuxagent.ga.update.UpdateHandler.get_latest_agent', return_value=latest_agent):
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
        self.prepare_agents()
        # Add a malformed error.json file in all existing agents
        for agent_dir in self.agent_dirs():
            error_file_path = os.path.join(agent_dir, AGENT_ERROR_FILE)
            with open(error_file_path, 'w') as f:
                f.write("")

        latest_agent = self.update_handler.get_latest_agent()
        self.assertEqual(latest_agent.name, 'WALinuxAgent-9.9.9.28', "Latest agent is invalid")

    def _test_run(self, invocations=1, calls=1, enable_updates=False, sleep_interval=(6,)):
        conf.get_autoupdate_enabled = Mock(return_value=enable_updates)

        def iterator(*_, **__):
            iterator.count += 1
            if iterator.count <= invocations:
                return True
            return False
        iterator.count = 0

        fileutil.write_file(conf.get_agent_pid_file_path(), ustr(42))

        with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler') as mock_handler:
            mock_handler.run_ext_handlers = Mock()
            with patch('azurelinuxagent.ga.update.get_monitor_handler') as mock_monitor:
                with patch.object(UpdateHandler, 'is_running') as mock_is_running:
                    mock_is_running.__get__ = Mock(side_effect=iterator)
                    with patch('azurelinuxagent.ga.remoteaccess.get_remote_access_handler') as mock_ra_handler:
                        with patch('azurelinuxagent.ga.update.get_env_handler') as mock_env:
                            with patch('azurelinuxagent.ga.update.get_collect_logs_handler') as mock_collect_logs:
                                with patch('azurelinuxagent.ga.update.get_send_telemetry_events_handler') as mock_telemetry_send_events:
                                    with patch('azurelinuxagent.ga.update.get_collect_telemetry_events_handler') as mock_event_collector:
                                        with patch('azurelinuxagent.ga.update.initialize_event_logger_vminfo_common_parameters'):
                                            with patch('azurelinuxagent.ga.update.is_log_collection_allowed', return_value=True):
                                                with patch('time.sleep') as sleep_mock:
                                                    with patch('sys.exit') as mock_exit:
                                                        if isinstance(os.getppid, MagicMock):
                                                            self.update_handler.run()
                                                        else:
                                                            with patch('os.getppid', return_value=42):
                                                                self.update_handler.run()

                                                    self.assertEqual(1, mock_handler.call_count)
                                                    self.assertEqual(calls, len([c for c in [call[0] for call in mock_handler.return_value.method_calls] if c == 'run']))
                                                    self.assertEqual(1, mock_ra_handler.call_count)
                                                    self.assertEqual(calls, len(mock_ra_handler.return_value.method_calls))
                                                    if calls > 0:
                                                        self.assertEqual(sleep_interval, sleep_mock.call_args[0])
                                                    self.assertEqual(1, mock_monitor.call_count)
                                                    self.assertEqual(1, mock_env.call_count)
                                                    self.assertEqual(1, mock_collect_logs.call_count)
                                                    self.assertEqual(1, mock_telemetry_send_events.call_count)
                                                    self.assertEqual(1, mock_event_collector.call_count)
                                                    self.assertEqual(1, mock_exit.call_count)

    def test_run(self):
        self._test_run()

    def test_run_stops_if_update_available(self):
        self.update_handler._check_and_download_agent_if_upgrade_available = Mock(return_value=True)
        self._test_run(invocations=0, calls=0, enable_updates=True)

    def test_run_stops_if_orphaned(self):
        with patch('os.getppid', return_value=1):
            self._test_run(invocations=0, calls=0, enable_updates=True)

    def test_run_clears_sentinel_on_successful_exit(self):
        self._test_run()
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_run_leaves_sentinel_on_unsuccessful_exit(self):
        self.update_handler._check_and_download_agent_if_upgrade_available = Mock(side_effect=Exception)
        self._test_run(invocations=1, calls=0, enable_updates=True)
        self.assertTrue(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_run_emits_restart_event(self):
        self.update_handler._emit_restart_event = Mock()
        self._test_run()
        self.assertEqual(1, self.update_handler._emit_restart_event.call_count)

    def test_set_agents_sets_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])
        self.assertTrue(len(self.update_handler.agents) > 0)
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))

    def test_set_agents_sorts_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])

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

    def _test_upgrade_available(
            self,
            base_version=FlexibleVersion(AGENT_VERSION),
            protocol=None,
            versions=None,
            count=20):

        if protocol is None:
            protocol = self._create_protocol(count=count, versions=versions)

        self.update_handler.protocol_util = protocol
        conf.get_autoupdate_gafamily = Mock(return_value=protocol.family)

        return self.update_handler._check_and_download_agent_if_upgrade_available(protocol, base_version=base_version)

    def test_upgrade_available_returns_true_on_first_use(self):
        self.assertTrue(self._test_upgrade_available())

    def test_upgrade_available_handles_missing_family(self):
        data_file = mockwiredata.DATA_FILE.copy()
        data_file["ext_conf"] = "wire/ext_conf_missing_family.xml"

        with mock_wire_protocol(data_file) as protocol:
            self.update_handler.protocol_util = protocol
            with patch('azurelinuxagent.common.logger.warn') as mock_logger:
                with patch('tests.ga.test_update.ProtocolMock.get_vmagent_pkgs', side_effect=ProtocolError):
                    self.assertFalse(self.update_handler._check_and_download_agent_if_upgrade_available(protocol, base_version=CURRENT_VERSION))
                    self.assertEqual(0, mock_logger.call_count)

    def test_upgrade_available_includes_old_agents(self):
        self.prepare_agents()

        old_version = self.agent_versions()[-1]
        old_count = old_version.version[-1]

        self.replicate_agents(src_v=old_version, count=old_count, increment=-1)
        all_count = len(self.agent_versions())

        self.assertTrue(self._test_upgrade_available(versions=self.agent_versions()))
        self.assertEqual(all_count, len(self.update_handler.agents))

    def test_upgrade_available_purges_old_agents(self):
        self.prepare_agents()
        agent_count = self.agent_count()
        self.assertEqual(20, agent_count)

        agent_versions = self.agent_versions()[:3]
        self.assertTrue(self._test_upgrade_available(versions=agent_versions))
        self.assertEqual(len(agent_versions), len(self.update_handler.agents))

        # Purging always keeps the running agent
        if CURRENT_VERSION not in agent_versions:
            agent_versions.append(CURRENT_VERSION)
        self.assertEqual(agent_versions, self.agent_versions())

    def test_update_available_returns_true_if_current_gets_blacklisted(self):
        self.update_handler._is_version_eligible = Mock(return_value=False)
        self.assertTrue(self._test_upgrade_available())

    def test_upgrade_available_skips_if_too_frequent(self):
        conf.get_autoupdate_frequency = Mock(return_value=10000)
        self.update_handler.last_attempt_time = time.time()
        self.assertFalse(self._test_upgrade_available())

    def test_upgrade_available_skips_if_when_no_new_versions(self):
        self.prepare_agents()
        base_version = self.agent_versions()[0] + 1
        self.update_handler._is_version_eligible = lambda x: x == base_version
        self.assertFalse(self._test_upgrade_available(base_version=base_version))

    def test_upgrade_available_skips_when_no_versions(self):
        self.assertFalse(self._test_upgrade_available(protocol=ProtocolMock()))

    def test_upgrade_available_skips_when_updates_are_disabled(self):
        conf.get_autoupdate_enabled = Mock(return_value=False)
        self.assertFalse(self._test_upgrade_available())

    def test_upgrade_available_sorts(self):
        self.prepare_agents()
        self._test_upgrade_available()

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version

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

    @patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False)
    def test_update_happens_when_extensions_disabled(self, _):
        """
        Although the extension enabled config will not get checked
        before an update is found, this test attempts to ensure that
        behavior never changes.
        """
        self.update_handler._check_and_download_agent_if_upgrade_available = Mock(return_value=True)
        self._test_run(invocations=0, calls=0, enable_updates=True, sleep_interval=(300,))

    @patch("azurelinuxagent.common.logger.info")
    @patch("azurelinuxagent.ga.update.add_event")
    def test_telemetry_heartbeat_creates_event(self, patch_add_event, patch_info, *_):
        update_handler = get_update_handler()
        mock_protocol = WireProtocol("foo.bar")

        update_handler.last_telemetry_heartbeat = datetime.utcnow() - timedelta(hours=1)
        update_handler._send_heartbeat_telemetry(mock_protocol)
        self.assertEqual(1, patch_add_event.call_count)
        self.assertTrue(any(call_args[0] == "[HEARTBEAT] Agent {0} is running as the goal state agent {1}"
                            for call_args in patch_info.call_args), "The heartbeat was not written to the agent's log")

    @staticmethod
    def _get_test_ext_handler_instance(protocol, name="OSTCExtensions.ExampleHandlerLinux", version="1.0.0"):
        eh = Extension(name=name)
        eh.version = version
        return ExtHandlerInstance(eh, protocol)

    def test_it_should_recreate_handler_env_on_service_startup(self):
        iterations = 5

        with _get_update_handler(iterations) as (update_handler, protocol):
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
        with _get_update_handler(iterations) as (update_handler, protocol):
            with patch("azurelinuxagent.common.agent_supported_feature._ETPFeature.is_supported", True):
                update_handler.set_iterations(1)
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

        self.assertTrue(update_handler.exit_mock.called, "The process should have exited")
        exit_args, _ = update_handler.exit_mock.call_args
        self.assertEqual(exit_args[0], 0, "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
            patch_warn.call_args_list))
        self.assertEqual(0, len(executed_firewall_commands), "firewall-cmd should not be called at all")
        self.assertTrue(any(
            "Not setting up persistent firewall rules as OS.EnableFirewall=False" == args[0] for (args, _) in
            patch_info.call_args_list), "Info not logged properly, got: {0}".format(patch_info.call_args_list))

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

        self.assertTrue(update_handler.exit_mock.called, "The process should have exited")
        exit_args, _ = update_handler.exit_mock.call_args
        self.assertEqual(exit_args[0], 0, "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
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
                with patch.object(osutil, '_enable_firewall', True):
                    # drop rule is present
                    mock_iptables.set_command(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination), exit_code=0)
                    # non root tcp iptable rule is absent
                    mock_iptables.set_command(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination), exit_code=1)
                    update_handler.run(debug=True)

                    drop_check_command = TestOSUtil._command_to_string(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_check_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_insert_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.INSERT_COMMAND, mock_iptables.destination))

                    # Filtering the mock iptable command calls with only the once related to this test.
                    filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if cmd in [drop_check_command, accept_tcp_check_rule, accept_tcp_insert_rule]]

                    self.assertEqual(len(filtered_mock_iptable_calls), 3, "Incorrect number of calls to iptables: [{0}]".format(mock_iptables.command_calls))
                    self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                     "The first command should check the drop rule")
                    self.assertEqual(filtered_mock_iptable_calls[1], accept_tcp_check_rule,
                                     "The second command should check the accept rule")
                    self.assertEqual(filtered_mock_iptable_calls[2], accept_tcp_insert_rule,
                                     "The third command should add the accept rule")

    def test_it_should_not_set_dns_tcp_iptable_if_drop_unavailable(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with _get_update_handler(test_data=DATA_FILE) as (update_handler, _):
                with patch.object(osutil, '_enable_firewall', True):
                    # drop rule is not available
                    mock_iptables.set_command(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination), exit_code=1)

                    update_handler.run(debug=True)

                    drop_check_command = TestOSUtil._command_to_string(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_check_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_insert_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.INSERT_COMMAND, mock_iptables.destination))

                    # Filtering the mock iptable command calls with only the once related to this test.
                    filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if cmd in [drop_check_command, accept_tcp_check_rule, accept_tcp_insert_rule]]

                    self.assertEqual(len(filtered_mock_iptable_calls), 1, "Incorrect number of calls to iptables: [{0}]".format(mock_iptables.command_calls))
                    self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                     "The first command should check the drop rule")

    def test_it_should_not_set_dns_tcp_iptable_if_drop_and_accept_available(self):

        with TestOSUtil._mock_iptables() as mock_iptables:
            with _get_update_handler(test_data=DATA_FILE) as (update_handler, _):
                with patch.object(osutil, '_enable_firewall', True):
                    # drop rule is available
                    mock_iptables.set_command(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination), exit_code=0)
                    # non root tcp iptable rule is available
                    mock_iptables.set_command(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination), exit_code=0)

                    update_handler.run(debug=True)

                    drop_check_command = TestOSUtil._command_to_string(osutil.get_firewall_drop_command(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_check_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.CHECK_COMMAND, mock_iptables.destination))
                    accept_tcp_insert_rule = TestOSUtil._command_to_string(osutil.get_accept_tcp_rule(mock_iptables.wait, AddFirewallRules.INSERT_COMMAND, mock_iptables.destination))

                    # Filtering the mock iptable command calls with only the once related to this test.
                    filtered_mock_iptable_calls = [cmd for cmd in mock_iptables.command_calls if cmd in [drop_check_command, accept_tcp_check_rule, accept_tcp_insert_rule]]

                    self.assertEqual(len(filtered_mock_iptable_calls), 2, "Incorrect number of calls to iptables: [{0}]".format(mock_iptables.command_calls))
                    self.assertEqual(filtered_mock_iptable_calls[0], drop_check_command,
                                     "The first command should check the drop rule")
                    self.assertEqual(filtered_mock_iptable_calls[1], accept_tcp_check_rule,
                                     "The second command should check the accept rule")

    @contextlib.contextmanager
    def _setup_test_for_ext_event_dirs_retention(self):
        try:
            with _get_update_handler(test_data=DATA_FILE_MULTIPLE_EXT) as (update_handler, protocol):
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
        with _get_update_handler(iterations=1) as (update_handler, protocol):
            with patch.object(conf, "get_enable_ga_versioning", return_value=True):
                with patch.object(conf, "get_autoupdate_gafamily", return_value="Prod"):
                    with patch("azurelinuxagent.common.logger.warn") as patch_warn:

                        protocol.aggregate_status = None
                        protocol.incarnation = 1

                        def mock_http_put(url, *args, **_):
                            if HttpRequestPredicates.is_host_plugin_status_request(url):
                                # Skip reading the HostGA request data as its encoded
                                return MockHttpResponse(status=500)
                            protocol.aggregate_status = json.loads(args[0])
                            return MockHttpResponse(status=201)

                        def update_goal_state_and_run_handler():
                            protocol.incarnation += 1
                            protocol.mock_wire_data.set_incarnation(protocol.incarnation)
                            self._add_write_permission_to_goal_state_files()
                            update_handler.set_iterations(1)
                            update_handler.run(debug=True)
                            self.assertTrue(update_handler.exit_mock.called, "The process should have exited")
                            exit_args, _ = update_handler.exit_mock.call_args
                            self.assertEqual(exit_args[0], 0,
                                             "Exit code should be 0; List of all warnings logged by the agent: {0}".format(
                                                 patch_warn.call_args_list))

                        protocol.set_http_handlers(http_put_handler=mock_http_put)

                        # Case 1: No requested version in GS; updateStatus should not be reported
                        update_goal_state_and_run_handler()
                        self.assertFalse("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                         "updateStatus should not be reported if not asked in GS")

                        # Case 2: Requested version in GS != Current Version; updateStatus should be error
                        protocol.mock_wire_data.set_extension_config("wire/ext_conf_requested_version.xml")
                        update_goal_state_and_run_handler()
                        self.assertTrue("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                        "updateStatus should be in status blob. Warns: {0}".format(patch_warn.call_args_list))
                        update_status = protocol.aggregate_status['aggregateStatus']['guestAgentStatus']["updateStatus"]
                        self.assertEqual(VMAgentUpdateStatuses.Error, update_status['status'], "Status should be an error")
                        self.assertEqual(update_status['expectedVersion'], "9.9.9.10", "incorrect version reported")
                        self.assertEqual(update_status['code'], 1, "incorrect code reported")

                        # Case 3: Requested version in GS == Current Version; updateStatus should be Success
                        protocol.mock_wire_data.set_extension_config_requested_version(str(CURRENT_VERSION))
                        update_goal_state_and_run_handler()
                        self.assertTrue("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                        "updateStatus should be reported if asked in GS")
                        update_status = protocol.aggregate_status['aggregateStatus']['guestAgentStatus']["updateStatus"]
                        self.assertEqual(VMAgentUpdateStatuses.Success, update_status['status'], "Status should be successful")
                        self.assertEqual(update_status['expectedVersion'], str(CURRENT_VERSION), "incorrect version reported")
                        self.assertEqual(update_status['code'], 0, "incorrect code reported")

                        # Case 4: Requested version removed in GS; no updateStatus should be reported
                        protocol.mock_wire_data.reload()
                        update_goal_state_and_run_handler()
                        self.assertFalse("updateStatus" in protocol.aggregate_status['aggregateStatus']['guestAgentStatus'],
                                         "updateStatus should not be reported if not asked in GS")


class TestAgentUpgrade(UpdateTestCase):

    @contextlib.contextmanager
    def create_conf_mocks(self, hotfix_frequency, normal_frequency):
        # Disabling extension processing to speed up tests as this class deals with testing agent upgrades
        with patch("azurelinuxagent.common.conf.get_extensions_enabled", return_value=False):
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=True):
                with patch("azurelinuxagent.common.conf.get_autoupdate_frequency", return_value=0.001):
                    with patch("azurelinuxagent.common.conf.get_hotfix_upgrade_frequency",
                               return_value=hotfix_frequency):
                        with patch("azurelinuxagent.common.conf.get_normal_upgrade_frequency",
                                   return_value=normal_frequency):
                            yield

    @contextlib.contextmanager
    def __get_update_handler(self, iterations=1, test_data=None, hotfix_frequency=1.0, normal_frequency=2.0,
                             reload_conf=None):

        test_data = DATA_FILE if test_data is None else test_data

        with _get_update_handler(iterations, test_data) as (update_handler, protocol):

            def get_handler(url, **kwargs):
                if reload_conf is not None:
                    reload_conf(url, protocol.mock_wire_data)

                if HttpRequestPredicates.is_agent_package_request(url):
                    agent_pkg = load_bin_data(self._get_agent_file_name(), self._agent_zip_dir)
                    return ResponseMock(response=agent_pkg)
                return protocol.mock_wire_data.mock_http_get(url, **kwargs)

            protocol.set_http_handlers(http_get_handler=get_handler)
            with self.create_conf_mocks(hotfix_frequency, normal_frequency):
                with patch("azurelinuxagent.ga.update.add_event") as mock_telemetry:
                    yield update_handler, mock_telemetry

    def __assert_exit_code_successful(self, exit_mock):
        self.assertTrue(exit_mock.called, "The process should have exited")
        exit_args, _ = exit_mock.call_args
        self.assertEqual(exit_args[0], 0, "Exit code should be 0")

    def __assert_upgrade_telemetry_emitted(self, mock_telemetry, upgrade_type=AgentUpgradeType.Normal):
        upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                              '{0} Agent upgrade discovered, updating to WALinuxAgent-99999.0.0.0 -- exiting'.format(
                                  upgrade_type) in kwarg['message'] and kwarg[
                                  'op'] == WALAEventOperation.AgentUpgrade]
        self.assertEqual(1, len(upgrade_event_msgs), "Agent not upgraded properly")

    def __assert_agent_directories_available(self, versions):
        for version in versions:
            self.assertTrue(os.path.exists(self.agent_dir(version)), "Agent directory {0} not found".format(version))

    def __assert_no_agent_upgrade_telemetry(self, mock_telemetry):
        self.assertEqual(0, len([kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                 "Agent upgrade discovered, updating to" in kwarg['message'] and kwarg[
                                     'op'] == WALAEventOperation.AgentUpgrade]), "Unwanted upgrade")

    def test_it_should_upgrade_agent_on_process_start_if_auto_upgrade_enabled(self):
        with self.__get_update_handler(iterations=10) as (update_handler, mock_telemetry):

            update_handler.run(debug=True)

            self.__assert_exit_code_successful(update_handler.exit_mock)
            self.assertEqual(1, update_handler.get_iterations(), "Update handler should've exited after the first run")
            self.__assert_agent_directories_available(versions=["99999.0.0.0"])
            self.__assert_upgrade_telemetry_emitted(mock_telemetry)

    def test_it_should_download_new_agents_and_not_auto_upgrade_if_not_permitted(self):
        no_of_iterations = 10
        data_file = DATA_FILE.copy()
        data_file['ga_manifest'] = "wire/ga_manifest_no_upgrade.xml"

        def reload_conf(url, mock_wire_data):
            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_ga_manifest_request(url) and mock_wire_data.call_counts["manifest_of_ga.xml"] >= no_of_iterations/2:
                reload_conf.call_count += 1
                # Ensure the first set of versions were downloaded as part of the first manifest
                self.__assert_agent_directories_available(versions=["1.0.0", "1.1.0", "1.2.0"])
                # As per our current agent upgrade model, we don't rely on an incarnation update to upgrade the agent. Mocking the same
                mock_wire_data.data_files["ga_manifest"] = "wire/ga_manifest.xml"
                mock_wire_data.reload()

        reload_conf.call_count = 0

        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, hotfix_frequency=10,
                                       normal_frequency=10, reload_conf=reload_conf) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Ensure the conf reload was called")
            self.__assert_exit_code_successful(update_handler.exit_mock)
            self.assertEqual(no_of_iterations, update_handler.get_iterations(), "Update handler should've run its course")
            # Ensure the new agent versions were also downloaded once the manifest was updated
            self.__assert_agent_directories_available(versions=["2.0.0", "2.1.0", "99999.0.0.0"])
            self.__assert_no_agent_upgrade_telemetry(mock_telemetry)

    def test_it_should_upgrade_agent_in_given_time_window_if_permitted(self):
        data_file = DATA_FILE.copy()
        data_file['ga_manifest'] = "wire/ga_manifest_no_upgrade.xml"

        def reload_conf(url, mock_wire_data):
            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_ga_manifest_request(url) and mock_wire_data.call_counts["manifest_of_ga.xml"] >= 2:
                reload_conf.call_count += 1
                # Ensure no new agent available so far
                self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")), "New agent directory should not be found")
                # As per our current agent upgrade model, we don't rely on an incarnation update to upgrade the agent. Mocking the same
                mock_wire_data.data_files["ga_manifest"] = "wire/ga_manifest.xml"
                mock_wire_data.reload()

        reload_conf.call_count = 0
        test_normal_frequency = 0.1
        with self.__get_update_handler(iterations=50, test_data=data_file, reload_conf=reload_conf,
                                       normal_frequency=test_normal_frequency) as (update_handler, mock_telemetry):
            start_time = time.time()
            update_handler.run(debug=True)
            diff = time.time() - start_time

            self.assertGreater(reload_conf.call_count, 0, "Ensure the conf reload was called")
            self.__assert_exit_code_successful(update_handler.exit_mock)
            self.assertGreaterEqual(update_handler.get_iterations(), 3,
                                    "Update handler should've run at least until the new GA was available")
            # A bare-bone check to ensure that the agent waited for the new agent at least for the preset frequency time
            self.assertGreater(diff, test_normal_frequency, "The test run should be at least greater than the set frequency")
            self.__assert_agent_directories_available(versions=["99999.0.0.0"])
            self.__assert_upgrade_telemetry_emitted(mock_telemetry)

    def test_it_should_not_auto_upgrade_if_auto_update_disabled(self):
        with self.__get_update_handler(iterations=10) as (update_handler, mock_telemetry):
            with patch("azurelinuxagent.common.conf.get_autoupdate_enabled", return_value=False):
                update_handler.run(debug=True)

                self.__assert_exit_code_successful(update_handler.exit_mock)
                self.assertGreaterEqual(update_handler.get_iterations(), 10, "Update handler should've run 10 times")
                self.__assert_no_agent_upgrade_telemetry(mock_telemetry)
                self.assertFalse(os.path.exists(self.agent_dir("99999.0.0.0")),
                                 "New agent directory should not be found")

    def test_it_should_not_auto_upgrade_if_corresponding_time_not_elapsed(self):
        # On Normal upgrade, should not upgrade if Hotfix time elapsed
        no_of_iterations = 10
        data_file = DATA_FILE.copy()
        data_file['ga_manifest'] = "wire/ga_manifest_no_upgrade.xml"

        def reload_conf(url, mock_wire_data):
            # This function reloads the conf mid-run to mimic an actual customer scenario
            if HttpRequestPredicates.is_ga_manifest_request(url) and mock_wire_data.call_counts["manifest_of_ga.xml"] >= no_of_iterations / 2:
                reload_conf.call_count += 1
                # As per our current agent upgrade model, we don't rely on an incarnation update to upgrade the agent. Mocking the same
                mock_wire_data.data_files["ga_manifest"] = "wire/ga_manifest.xml"
                mock_wire_data.reload()

        reload_conf.call_count = 0

        with self.__get_update_handler(iterations=no_of_iterations, test_data=data_file, hotfix_frequency=0.01,
                                       normal_frequency=10, reload_conf=reload_conf) as (update_handler, mock_telemetry):
            update_handler.run(debug=True)

            self.assertGreater(reload_conf.call_count, 0, "Ensure the conf reload was called")
            self.__assert_exit_code_successful(update_handler.exit_mock)
            self.assertEqual(no_of_iterations, update_handler.get_iterations(), "Update handler didn't run completely")
            self.__assert_no_agent_upgrade_telemetry(mock_telemetry)
            upgrade_event_msgs = [kwarg['message'] for _, kwarg in mock_telemetry.call_args_list if
                                  kwarg['op'] == WALAEventOperation.AgentUpgrade]
            self.assertGreater(len([msg for msg in upgrade_event_msgs if
                                    'Discovered new {0} upgrade WALinuxAgent-99999.0.0.0; Will upgrade on or after'.format(
                                        AgentUpgradeType.Normal) in msg]), 0, "Error message not propagated properly")


@patch('azurelinuxagent.ga.update.get_collect_telemetry_events_handler')
@patch('azurelinuxagent.ga.update.get_send_telemetry_events_handler')
@patch('azurelinuxagent.ga.update.get_collect_logs_handler')
@patch('azurelinuxagent.ga.update.get_monitor_handler')
@patch('azurelinuxagent.ga.update.get_env_handler')
class MonitorThreadTest(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.event_patch = patch('azurelinuxagent.common.event.add_event')
        currentThread().setName("ExtHandler")
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
                            with patch('azurelinuxagent.ga.update.initialize_event_logger_vminfo_common_parameters'):
                                with patch('azurelinuxagent.common.cgroupapi.CGroupsApi.cgroups_supported', return_value=False):  # skip all cgroup stuff
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


class ProtocolMock(object):
    def __init__(self, family="TestAgent", etag=42, versions=None, client=None):
        self.family = family
        self.client = client
        self.call_counts = {
            "get_vmagent_manifests": 0,
            "get_vmagent_pkgs": 0,
            "update_goal_state": 0
        }
        self.goal_state_is_stale = False
        self.etag = etag
        self.versions = versions if versions is not None else []
        self.create_manifests()
        self.create_packages()

    def emulate_stale_goal_state(self):
        self.goal_state_is_stale = True

    def create_manifests(self):
        self.agent_manifests = []
        if len(self.versions) <= 0:
            return

        if self.family is not None:
            manifest = VMAgentManifest(family=self.family)
            for i in range(0, 10):
                manifest.uris.append("https://nowhere.msft/agent/{0}".format(i))
            self.agent_manifests.append(manifest)

    def create_packages(self):
        self.agent_packages = ExtHandlerPackageList()
        if len(self.versions) <= 0:
            return

        for version in self.versions:
            package = ExtHandlerPackage(str(version))
            for i in range(0, 5):
                package_uri = "https://nowhere.msft/agent_pkg/{0}".format(i)
                package.uris.append(package_uri)
            self.agent_packages.versions.append(package)

    def get_protocol(self):
        return self

    def get_vmagent_manifests(self):
        self.call_counts["get_vmagent_manifests"] += 1
        if self.goal_state_is_stale:
            self.goal_state_is_stale = False
            raise ResourceGoneError()
        return self.agent_manifests, self.etag

    def get_vmagent_pkgs(self, manifest):  # pylint: disable=unused-argument
        self.call_counts["get_vmagent_pkgs"] += 1
        if self.goal_state_is_stale:
            self.goal_state_is_stale = False
            raise ResourceGoneError()
        return self.agent_packages

    def update_goal_state(self):
        self.call_counts["update_goal_state"] += 1


class ResponseMock(Mock):
    def __init__(self, status=restutil.httpclient.OK, response=None, reason=None):
        Mock.__init__(self)
        self.status = status
        self.reason = reason
        self.response = response

    def read(self):
        return self.response


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
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            self.assertTrue(update_handler._try_update_goal_state(protocol), "try_update_goal_state should have succeeded")

    def test_it_should_return_false_on_failure(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            def http_get_handler(url, *_, **__):
                if self.is_goal_state_request(url):
                    return HttpError('Exception to fake an error retrieving the goal state')
                return None
            protocol.set_http_handlers(http_get_handler=http_get_handler)

            update_handler = get_update_handler()
            self.assertFalse(update_handler._try_update_goal_state(protocol), "try_update_goal_state should have failed")

    def test_it_should_update_the_goal_state(self):
        update_handler = get_update_handler()
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            protocol.mock_wire_data.set_incarnation(12345)

            # the first goal state should produce an update
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(protocol.get_incarnation(), '12345', "The goal state was not updated (received unexpected incarnation)")

            # no changes in the goal state should not produce an update
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(protocol.get_incarnation(), '12345', "The goal state should not be updated (received unexpected incarnation)")

            # a new  goal state should produce an update
            protocol.mock_wire_data.set_incarnation(6789)
            update_handler._try_update_goal_state(protocol)
            self.assertEqual(protocol.get_incarnation(), '6789', "The goal state was not updated (received unexpected incarnation)")

    def test_it_should_log_errors_only_when_the_error_state_changes(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
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
            warnings = lambda: logger_calls(r'call.warn\(.*An error occurred while retrieving the goal state.*')
            periodic_warnings = lambda: logger_calls(r'call.periodic_warn\(.*Attempts to retrieve the goal state are failing.*')
            success_messages = lambda: logger_calls(r'call.info\(.*Retrieving the goal state recovered from previous errors.*')
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

                w = warnings()
                pw = periodic_warnings()
                self.assertEqual(1, len(w), "A failure should have produced a warning: [{0}]".format(w))
                self.assertEqual(1, len(pw), "A failure should have produced a periodic warning: [{0}]".format(pw))

                gs = goal_state_events()
                self.assertTrue(len(gs) == 1 and 'is_success=False' in gs[0], "A failure should produce a telemetry event (success=false): [{0}]".format(gs))

            #
            # ... and errors continue happening...
            #
            with create_log_and_telemetry_mocks() as (logger, add_event):
                update_handler._try_update_goal_state(protocol)
                update_handler._try_update_goal_state(protocol)
                update_handler._try_update_goal_state(protocol)

                w = warnings()
                pw = periodic_warnings()
                self.assertTrue(len(w) == 0, "Subsequent failures should not produce warnings: [{0}]".format(w))
                self.assertEqual(len(pw), 3, "Subsequent failures should produce periodic warnings: [{0}]".format(pw))

                tc = telemetry_calls()
                self.assertTrue(len(tc) == 0, "Subsequent failures should not produce any telemetry events: [{0}]".format(tc))

            #
            # ... until we finally succeed
            #
            fail_goal_state_request = False
            with create_log_and_telemetry_mocks() as (logger, add_event):
                update_handler._try_update_goal_state(protocol)

                s = success_messages()
                w = warnings()
                pw = periodic_warnings()
                self.assertEqual(len(s), 1, "Recovering after failures should have produced an info message: [{0}]".format(s))
                self.assertTrue(len(w) == 0 and len(pw) == 0, "Recovering after failures should have not produced any warnings: [{0}] [{1}]".format(w, pw))

                gs = goal_state_events()
                self.assertTrue(len(gs) == 1 and 'is_success=True' in gs[0], "Recovering after failures should produce a telemetry event (success=true): [{0}]".format(gs))


def _create_update_handler():
    """
    Creates an UpdateHandler in which agent updates are mocked as a no-op.
    """
    update_handler = get_update_handler()
    update_handler._check_and_download_agent_if_upgrade_available = Mock(return_value=False)
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

            # process a goal state
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
            self.assertEqual(1, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have been called on the first goal state")
            self.assertEqual(1, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on the first goal state")
            self.assertEqual(1, remote_access_handler.run.call_count, "remote_access_handler.run() should have been called on the first goal state")

            # process the same goal state
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
            self.assertEqual(1, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have not been called on the same goal state")
            self.assertEqual(2, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on the same goal state")
            self.assertEqual(1, remote_access_handler.run.call_count, "remote_access_handler.run() should not have been called on the same goal state")

            # process a new goal state
            exthandlers_handler.protocol.mock_wire_data.set_incarnation(999)
            exthandlers_handler.protocol.client.update_goal_state()
            update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
            self.assertEqual(2, exthandlers_handler.run.call_count, "exthandlers_handler.run() should have been called on a new goal state")
            self.assertEqual(3, exthandlers_handler.report_ext_handlers_status.call_count, "exthandlers_handler.report_ext_handlers_status() should have been called on a new goal state")
            self.assertEqual(2, remote_access_handler.run.call_count, "remote_access_handler.run() should have been called on a new goal state")


class ReportStatusTestCase(AgentTestCase):
    """
    Tests for UpdateHandler._report_status()
    """

    def setUp(self):
        self.patches = [
            patch("time.sleep", side_effect=lambda _: mock_sleep(0.001)),
            patch("sys.exit")
        ]

        for p in self.patches:
            p.start()

        return AgentTestCase.setUp(self)

    def tearDown(self):
        
        for p in self.patches:
            p.stop()

        return AgentTestCase.tearDown(self)

    @staticmethod
    @contextlib.contextmanager
    def _mock_update_handler(iterations=1, **kwargs):
        """
        Creates an UpdateHandler instance that will run n iterations.

        Can be supplied keyword args for:
            *   mock_wire_data_file: This arg is treated like mock_wire_protocol
                would. Defaults to mockwiredata.DATA_FILE_STATUS_BLOB
            *   http_<action>_handler where action is get, put, or post: This arg
                is treated like mock_wire_protocol would.
        
        Returned UpdateHandler instance has its protocol mocked via mock_wire_protocol.
        """
        
        # Build the side_effect list for the UpdateHandler.is_running PropertyMock.
        # Return True for the first n iterations followed by a single False to stop
        # and then another True because the current UpdateHandler implementation
        # does a __set__ during shutdown.
        is_running_return_values = [True] * iterations + [False, True]
        is_running_patch = patch.object(UpdateHandler, "is_running", PropertyMock(side_effect=is_running_return_values))

        mock_http_get = kwargs.get("http_get_handler")
        mock_http_put = kwargs.get("http_put_handler")
        mock_http_post = kwargs.get("http_post_handler")

        mock_wire_data_file = kwargs.get("mock_wire_data_file", mockwiredata.DATA_FILE_STATUS_BLOB)

        try:
            with mock_wire_protocol(mock_wire_data_file, mock_http_get, mock_http_post, mock_http_put) as protocol:
                update_handler = get_update_handler()
                
                update_handler.protocol_util.get_protocol = Mock(return_value=protocol)

                is_running_patch.start()
                yield update_handler
        finally:
            is_running_patch.stop()

    @staticmethod
    def _fail_goal_state_fetch(url, **_):
        """
        For each goal state requested, returns values in order before failing with an
        HttpError. Is useful for getting the agent into a specific state before causing
        a failure.

        Relies on this function to have the property return_vals populated with a list
        of values to be returned in order. Any `None` in the list will cause the mock wire
        data to be queried and returned, and thus functions as a sort of default.
        """
        if not HttpRequestPredicates.is_goal_state_request(url):
            # url does not represent a request for a goal state; return None so
            # that the mock_wire_protocol will return whatever data is in the mock
            # wire data object (as per the mock_wire_protocol's docstring).
            return None
        try:
            return ReportStatusTestCase._fail_goal_state_fetch.return_vals.pop()
        except IndexError:
            raise HttpError()

    def test_update_handler_should_report_status_even_on_failed_goal_state_fetch(self):

        try:
            # Returning None forces the mock wire data to return the contents in the static
            # files, as documented in mock_wire_protocol's docstring. We return thrice:
            # once for protocol initialization, once for HostGAPlugin initialization,
            # and once for the initial call in run().
            # TODO: This test has too much knowledge of the protocol with the wireserver; rewrite it
            #       at the level of UpdateHanlder._process_goal_state, which is where the tested
            #       logic resides.
            #
            # TODO: For the same reason, the test below (commented out) needs to be rewritten
            ReportStatusTestCase._fail_goal_state_fetch.return_vals = [None, None, None]

            with ReportStatusTestCase._mock_update_handler(http_get_handler=ReportStatusTestCase._fail_goal_state_fetch) as update_handler:
                update_handler.run(debug=True)

                mock_protocol = update_handler.protocol_util.get_protocol()
                self.assertEqual(mock_protocol.mock_wire_data.call_counts['/StatusBlob'], 1,
                    "Expected a single status blob to be uploaded")
        finally:
            # clean up the static variable
            del ReportStatusTestCase._fail_goal_state_fetch.return_vals

    @skip_if_predicate_true(lambda: True, "See TODO comment in test_update_handler_should_report_status_even_on_failed_goal_state_fetch")
    def test_update_handler_should_report_status_for_cached_goal_state_on_failed_fetch(self):

        try:
            # Adds one return to the test above (test_upload_vm_status_even_on_failed_goal_state_fetch).
            # The third (and last) return is to allow for the extensions to be processed once so that
            # we will have extension status to test for.
            ReportStatusTestCase._fail_goal_state_fetch.return_vals = [ None, None, None, None ]

            with ReportStatusTestCase._mock_update_handler(iterations=2,
                http_get_handler=ReportStatusTestCase._fail_goal_state_fetch) as update_handler:
                update_handler.run(debug=True)

                wire_data = update_handler.protocol_util.get_protocol().mock_wire_data
                self.assertEqual(wire_data.call_counts['/StatusBlob'], 2,
                    "Expected two status blobs to be uploaded, one for each iteration of the run loop.")

                latest_status_blob_str = wire_data.status_blobs[-1]
                latest_status_blob = json.loads(latest_status_blob_str)

                ext_handler_statuses = latest_status_blob.get('aggregateStatus', {}).get("handlerAggregateStatus")
                self.assertEqual(1, len(ext_handler_statuses), "Expected status for a single extension")

                expectedHandlerInfo = {
                    "handlerName": "OSTCExtensions.ExampleHandlerLinux",
                    "handlerVersion": "1.0.0"
                }

                for key, expected_val in expectedHandlerInfo.items():
                    actual_val = ext_handler_statuses[0].get(key)

                    msg = "Extension information '{0}' did not match the provided extension.".format(key)
                    self.assertEqual(actual_val, expected_val, msg)

        finally:
            # clean up the static variable
            del ReportStatusTestCase._fail_goal_state_fetch.return_vals

    def test_report_status_should_log_errors_only_once_per_goal_state(self):
        update_handler = _create_update_handler()
        with _mock_exthandlers_handler() as exthandlers_handler:
            with patch("azurelinuxagent.ga.update.logger.warn") as logger_warn:
                update_handler._report_status(exthandlers_handler, False)
                self.assertEqual(0, logger_warn.call_count, "UpdateHandler._report_status() should not report WARNINGS when there are no errors")

                with patch("azurelinuxagent.ga.update.ExtensionsSummary.__init__", return_value=Exception("TEST EXCEPTION")):  # simulate an error during _report_status()
                    update_handler._report_status(exthandlers_handler, False)
                    update_handler._report_status(exthandlers_handler, False)
                    update_handler._report_status(exthandlers_handler, False)
                    self.assertEqual(1, logger_warn.call_count, "UpdateHandler._report_status() should report only 1 WARNING when there are multiple errors within the same goal state")

                    exthandlers_handler.protocol.mock_wire_data.set_incarnation(999)
                    update_handler._try_update_goal_state(exthandlers_handler.protocol)
                    update_handler._report_status(exthandlers_handler, True)
                    self.assertEqual(2, logger_warn.call_count, "UpdateHandler._report_status() should continue reporting errors after a new goal state")


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

                    update_handler = _create_update_handler()
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period")

                    # the extension is transisioning, so we should still be using the initial goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period when the extension is transitioning")

                    # the goal state converged (the extension succeeded), so we should switch to the regular goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
                    self.assertEqual(goal_state_period, update_handler._goal_state_period, "Expected the regular goal state period after the goal state converged")

    def test_update_handler_should_switch_to_the_regular_goal_state_period_when_the_goal_state_does_not_converges(self):
        initial_goal_state_period, goal_state_period = 11111, 22222
        with patch('azurelinuxagent.common.conf.get_initial_goal_state_period', return_value=initial_goal_state_period):
            with patch('azurelinuxagent.common.conf.get_goal_state_period', return_value=goal_state_period):
                with _mock_exthandlers_handler([ExtensionStatusValue.transitioning, ExtensionStatusValue.transitioning]) as exthandlers_handler:
                    remote_access_handler = Mock()

                    update_handler = _create_update_handler()
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period")

                    # the extension is transisioning, so we should still be using the initial goal state period
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
                    self.assertEqual(initial_goal_state_period, update_handler._goal_state_period, "Expected the initial goal state period when the extension is transitioning")

                    # a new goal state arrives before the current goal state converged (the extension is transitioning), so we should switch to the regular goal state period
                    exthandlers_handler.protocol.mock_wire_data.set_incarnation(100)
                    update_handler._process_goal_state(exthandlers_handler, remote_access_handler)
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
