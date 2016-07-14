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

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.exception import UpdateError
from azurelinuxagent.common.protocol.restapi import *
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION
from azurelinuxagent.ga.update import *

NO_ERROR = {
    "last_failure" : 0.0,
    "failure_count" : 0,
    "was_fatal" : False
}

WITH_ERROR = {
    "last_failure" : 42.42,
    "failure_count" : 2,
    "was_fatal" : False
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


def get_agent_pkgs(in_dir=os.path.join(data_dir, "ga")):
    path = os.path.join(in_dir, AGENT_PKG_GLOB)
    return glob.glob(path)


def get_agents(in_dir=os.path.join(data_dir, "ga")):
    path = os.path.join(in_dir, AGENT_DIR_GLOB)
    return [a for a in glob.glob(path) if os.path.isdir(a)]


def get_agent_file_path():
    return get_agent_pkgs()[0]


def get_agent_file_name():
    return os.path.basename(get_agent_file_path())


def get_agent_path():
    return fileutil.trim_ext(get_agent_file_path(), "zip")


def get_agent_name():
    return os.path.basename(get_agent_path())


def get_agent_version():
    return FlexibleVersion(get_agent_name().split("-")[1])


def faux_logger():
    print("STDOUT message")
    print("STDERR message", file=sys.stderr)
    return DEFAULT


class UpdateTestCase(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        return

    def agent_bin(self, version):
        return "bin/{0}-{1}.egg".format(AGENT_NAME, version)

    def agent_count(self):
        return len(self.agent_dirs())

    def agent_dirs(self):
        return get_agents(in_dir=self.tmp_dir)

    def agent_dir(self, version):
        return os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, version))

    def agent_paths(self):
        paths = glob.glob(os.path.join(self.tmp_dir, "*"))
        paths.sort()
        return paths

    def agent_pkgs(self):
        return get_agent_pkgs(in_dir=self.tmp_dir)

    def agent_versions(self):
        v = [FlexibleVersion(AGENT_DIR_PATTERN.match(a).group(1)) for a in self.agent_dirs()]
        v.sort(reverse=True)
        return v

    def get_error_file(self, error_data=NO_ERROR):
        fp = tempfile.NamedTemporaryFile(mode="w")
        json.dump(error_data if error_data is not None else NO_ERROR, fp)
        fp.seek(0)
        return fp

    def create_error(self, error_data=NO_ERROR):
        with self.get_error_file(error_data) as path:
            return GuestAgentError(path.name)

    def copy_agents(self, *agents):
        if len(agents) <= 0:
            agents = get_agent_pkgs()
        for agent in agents:
            fileutil.copy_file(agent, to_dir=self.tmp_dir)
        return

    def expand_agents(self):
        for agent in self.agent_pkgs():
            zipfile.ZipFile(agent).extractall(os.path.join(
                self.tmp_dir,
                fileutil.trim_ext(agent, "zip")))
        return

    def prepare_agents(self, base_version=AGENT_VERSION, count=5, is_available=True):
        base_v = FlexibleVersion(base_version)

        # Ensure the test data is copied over
        agent_count = self.agent_count()
        if agent_count <= 0:
            self.copy_agents(get_agent_pkgs()[0])
            self.expand_agents()
            count -= 1
        
        # Determine the most recent agent version
        versions = self.agent_versions()
        src_v = FlexibleVersion(str(versions[0]))

        # If the most recent agent is newer the minimum requested, use the agent version
        if base_v < src_v:
            base_v = src_v

        # Create agent packages and directories
        return self.replicate_agents(
            src_v=src_v,
            count=count-agent_count,
            is_available=is_available)

    def remove_agents(self):
        for agent in self.agent_paths():
            try:
                if os.path.isfile(agent):
                    os.remove(agent)
                else:
                    shutil.rmtree(agent)
            except:
                pass
        return

    def replicate_agents(
        self,
        count=5,
        src_v=AGENT_VERSION,
        is_available=True,
        increment=1):
        from_path = self.agent_dir(src_v)
        dst_v = FlexibleVersion(str(src_v))
        for i in range(0,count):
            dst_v += increment
            to_path = self.agent_dir(dst_v)
            shutil.copyfile(from_path + ".zip", to_path + ".zip")
            shutil.copytree(from_path, to_path)
            shutil.move(
                os.path.join(to_path, self.agent_bin(src_v)),
                os.path.join(to_path, self.agent_bin(dst_v)))
            if not is_available:
                GuestAgent(to_path).mark_failure(is_fatal=True)
        
        return dst_v


class TestGuestAgentError(UpdateTestCase):
    def test_creation(self):
        self.assertRaises(TypeError, GuestAgentError)
        self.assertRaises(UpdateError, GuestAgentError, None)

        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        self.assertEqual(WITH_ERROR["last_failure"], err.last_failure)
        self.assertEqual(WITH_ERROR["failure_count"], err.failure_count)
        self.assertEqual(WITH_ERROR["was_fatal"], err.was_fatal)
        return

    def test_clear(self):
        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        err.clear()
        self.assertEqual(NO_ERROR["last_failure"], err.last_failure)
        self.assertEqual(NO_ERROR["failure_count"], err.failure_count)
        self.assertEqual(NO_ERROR["was_fatal"], err.was_fatal)
        return

    def test_load_preserves_error_state(self):
        with self.get_error_file(error_data=WITH_ERROR) as path:
            err = GuestAgentError(path.name)
            self.assertEqual(path.name, err.path)
        self.assertNotEqual(None, err)

        with self.get_error_file(error_data=NO_ERROR):
            err.load()
        self.assertEqual(WITH_ERROR["last_failure"], err.last_failure)
        self.assertEqual(WITH_ERROR["failure_count"], err.failure_count)
        self.assertEqual(WITH_ERROR["was_fatal"], err.was_fatal)
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

        for i in range(0, MAX_FAILURE):
            err.mark_failure()
        
        # Agent failed >= MAX_FAILURE, it should be blacklisted
        self.assertTrue(err.is_blacklisted)
        self.assertEqual(MAX_FAILURE, err.failure_count)
        
        # Clear old failure does not clear recent failure
        err.clear_old_failure()
        self.assertTrue(err.is_blacklisted)

        # Clear does remove old, outdated failures
        err.last_failure -= RETAIN_INTERVAL * 2
        err.clear_old_failure()
        self.assertFalse(err.is_blacklisted)
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
        self.copy_agents(get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, get_agent_name())
        return

    def tearDown(self):
        self.remove_agents()
        return

    def test_creation(self):
        self.assertRaises(UpdateError, GuestAgent, "A very bad file name")
        n = "{0}-a.bad.version".format(AGENT_NAME)
        self.assertRaises(UpdateError, GuestAgent, n)

        agent = GuestAgent(path=self.agent_path)
        self.assertNotEqual(None, agent)
        self.assertEqual(get_agent_name(), agent.name)
        self.assertEqual(get_agent_version(), agent.version)

        self.assertEqual(self.agent_path, agent.get_agent_dir())

        path = os.path.join(self.agent_path, AGENT_MANIFEST_FILE)
        self.assertEqual(path, agent.get_agent_manifest_path())

        self.assertEqual(
            os.path.join(self.agent_path, AGENT_ERROR_FILE),
            agent.get_agent_error_file())

        path = ".".join((os.path.join(conf.get_lib_dir(), get_agent_name()), "zip"))
        self.assertEqual(path, agent.get_agent_pkg_path())

        self.assertTrue(agent.is_downloaded)
        # Note: Agent will get blacklisted since the package for this test is invalid
        self.assertTrue(agent.is_blacklisted)
        self.assertFalse(agent.is_available)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_clear_error(self, mock_ensure):
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
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_is_available(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)

        self.assertFalse(agent.is_available)
        agent._unpack()
        self.assertTrue(agent.is_available)
        
        agent.mark_failure(is_fatal=True)
        self.assertFalse(agent.is_available)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_is_blacklisted(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(agent.is_blacklisted)

        agent._unpack()
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)
        
        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_is_downloaded(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(agent.is_downloaded)
        agent._unpack()
        self.assertTrue(agent.is_downloaded)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_mark_failure(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        agent.mark_failure()
        self.assertEqual(1, agent.error.failure_count)

        agent.mark_failure(is_fatal=True)
        self.assertEqual(2, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_unpack(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isdir(agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_unpack_fail(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        os.remove(agent.get_agent_pkg_path())
        self.assertRaises(UpdateError, agent._unpack)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_load_manifest(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        agent._unpack()
        agent._load_manifest()
        self.assertEqual(agent.manifest.get_enable_command(), agent.get_agent_cmd())
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_load_manifest_missing(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        os.remove(agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, agent._load_manifest)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_load_manifest_is_empty(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, agent._load_manifest)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_load_manifest_is_malformed(self, mock_ensure):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:
            file.write("This is not JSON data")
        self.assertRaises(UpdateError, agent._load_manifest)
        return

    def test_load_error(self):
        agent = GuestAgent(path=self.agent_path)
        agent.error = None

        agent._load_error()
        self.assertTrue(agent.error is not None)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download(self, mock_http_get, mock_ensure):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        mock_http_get.return_value= ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)
        agent._download()

        self.assertTrue(os.path.isfile(agent.get_agent_pkg_path()))
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download_fail(self, mock_http_get, mock_ensure):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        mock_http_get.return_value= ResponseMock(status=restutil.httpclient.SERVICE_UNAVAILABLE)
        
        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertRaises(UpdateError, agent._download)
        self.assertFalse(os.path.isfile(agent.get_agent_pkg_path()))
        self.assertFalse(agent.is_downloaded)
        return

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_ensure_downloaded(self, mock_http_get):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        mock_http_get.return_value= ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))
        self.assertTrue(agent.is_downloaded)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._download", side_effect=UpdateError)
    def test_ensure_downloaded_download_fails(self, mock_download):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertFalse(agent.error.was_fatal)
        self.assertFalse(agent.is_blacklisted)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack", side_effect=UpdateError)
    def test_ensure_downloaded_unpack_fails(self, mock_download, mock_unpack):
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest", side_effect=UpdateError)
    def test_ensure_downloaded_load_manifest_fails(self, mock_download, mock_unpack, mock_manifest):
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)
        return

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest")
    def test_ensure_download_skips_blacklisted(self, mock_download, mock_unpack, mock_manifest):
        agent = GuestAgent(path=self.agent_path)
        agent.clear_error()
        agent.mark_failure(is_fatal=True)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(0, mock_download.call_count)
        self.assertEqual(0, mock_unpack.call_count)
        self.assertEqual(0, mock_manifest.call_count)
        return


class TestUpdate(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.update_handler = get_update_handler()
        return

    def test_creation(self):
        self.assertTrue(self.update_handler.running)

        self.assertEqual(None, self.update_handler.last_etag)
        self.assertEqual(None, self.update_handler.last_attempt_time)

        self.assertEqual(0, len(self.update_handler.agents))

        self.assertEqual(None, self.update_handler.child_agent)
        self.assertEqual(None, self.update_handler.child_launch_time)
        self.assertEqual(0, self.update_handler.child_launch_attempts)
        self.assertEqual(None, self.update_handler.child_process)

        self.assertEqual(None, self.update_handler.signal_handler)
        return

    def _test_ensure_latest_agent(
            self,
            base_version=FlexibleVersion(AGENT_VERSION),
            protocol=None,
            versions=None):
        
        latest_version = self.prepare_agents()
        if versions is None or len(versions) <= 0:
            versions = [latest_version]

        etag = self.update_handler.last_etag if self.update_handler.last_etag is not None else 42
        if protocol is None:
            protocol = ProtocolMock(etag=etag, versions=versions)
        self.update_handler.protocol_util = protocol
        conf.get_autoupdate_gafamily = Mock(return_value=protocol.family)

        return self.update_handler._ensure_latest_agent(base_version=base_version)

    def test_ensure_latest_agent_returns_true_on_first_use(self):
        self.assertEqual(None, self.update_handler.last_etag)
        self.assertTrue(self._test_ensure_latest_agent())
        return

    def test_ensure_latest_agent_includes_old_agents(self):
        self.prepare_agents()

        old_count = FlexibleVersion(AGENT_VERSION).version[-1]
        old_version = self.agent_versions()[-1]

        self.replicate_agents(src_v=old_version, count=old_count, increment=-1)
        all_count = len(self.agent_versions())

        self.assertTrue(self._test_ensure_latest_agent(versions=self.agent_versions()))
        self.assertEqual(all_count, len(self.update_handler.agents))
        return

    def test_ensure_lastest_agent_purges_old_agents(self):
        self.prepare_agents()
        agent_count = self.agent_count()
        self.assertEqual(5, agent_count)
        
        agent_versions = self.agent_versions()[:3]
        self.assertTrue(self._test_ensure_latest_agent(versions=agent_versions))
        self.assertEqual(len(agent_versions), len(self.update_handler.agents))
        self.assertEqual(agent_versions, self.agent_versions())
        return

    def test_ensure_latest_agent_skips_if_too_frequent(self):
        conf.get_autoupdate_frequency = Mock(return_value=10000)
        self.update_handler.last_attempt_time = time.time()
        self.assertFalse(self._test_ensure_latest_agent())
        return

    def test_ensure_latest_agent_skips_when_etag_matches(self):
        self.update_handler.last_etag = 42
        self.assertFalse(self._test_ensure_latest_agent())
        return

    def test_ensure_latest_agent_skips_if_when_no_new_versions(self):
        self.prepare_agents()
        base_version = self.agent_versions()[0] + 1
        self.assertFalse(self._test_ensure_latest_agent(base_version=base_version))
        return

    def test_ensure_latest_agent_skips_when_no_versions(self):
        self.assertFalse(self._test_ensure_latest_agent(protocol=ProtocolMock()))
        return

    def test_ensure_latest_agent_skips_when_updates_are_disabled(self):
        conf.get_autoupdate_enabled = Mock(return_value=False)
        self.assertFalse(self._test_ensure_latest_agent())
        return

    def test_ensure_latest_agent_sorts(self):
        self.prepare_agents()
        self._test_ensure_latest_agent()

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version
        return

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
        return

    def test_evaluate_agent_health_ignores_installed_agent(self):
        self.update_handler._evaluate_agent_health(None)
        return

    def test_evaluate_agent_health_raises_exception_for_restarting_agent(self):
        self.update_handler.child_launch_time = time.time() - (4 * 60)
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 1
        self.assertRaises(Exception, self._test_evaluate_agent_health)
        return

    def test_evaluate_agent_health_will_not_raise_exception_for_long_restarts(self):
        self.update_handler.child_launch_time = time.time() - 24 * 60
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX
        self._test_evaluate_agent_health()
        return

    def test_evaluate_agent_health_will_not_raise_exception_too_few_restarts(self):
        self.update_handler.child_launch_time = time.time()
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 2
        self._test_evaluate_agent_health()
        return

    def test_evaluate_agent_health_resets_with_new_agent(self):
        self.update_handler.child_launch_time = time.time() - (4 * 60)
        self.update_handler.child_launch_attempts = CHILD_LAUNCH_RESTART_MAX - 1
        self._test_evaluate_agent_health(child_agent_index=1)
        self.assertEqual(1, self.update_handler.child_launch_attempts)
        return

    def test_filter_blacklisted_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))

        kept_agents = self.update_handler.agents[1::2]
        blacklisted_agents = self.update_handler.agents[::2]
        for agent in blacklisted_agents:
            agent.mark_failure(is_fatal=True)
        self.update_handler._filter_blacklisted_agents()
        self.assertEqual(kept_agents, self.update_handler.agents)
        return

    def test_get_latest_agent(self):
        latest_version = self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertEqual(len(get_agents(self.tmp_dir)), len(self.update_handler.agents))
        self.assertEqual(latest_version, latest_agent.version)
        return

    def test_get_latest_agent_no_updates(self):
        self.assertEqual(None, self.update_handler.get_latest_agent())
        return

    def test_get_latest_agent_skip_updates(self):
        conf.get_autoupdate_enabled = Mock(return_value=False)
        self.assertEqual(None, self.update_handler.get_latest_agent())
        return

    def test_get_latest_agent_skips_unavailable(self):
        self.prepare_agents()
        prior_agent = self.update_handler.get_latest_agent()

        latest_version = self.prepare_agents(count=self.agent_count()+1, is_available=False)
        latest_path = os.path.join(self.tmp_dir, "{0}-{1}".format(AGENT_NAME, latest_version))
        self.assertFalse(GuestAgent(latest_path).is_available)

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.version < latest_version)
        self.assertEqual(latest_agent.version, prior_agent.version)
        return

    def test_load_agents(self):
        self.prepare_agents()

        self.assertTrue(0 <= len(self.update_handler.agents))
        self.update_handler._load_agents()
        self.assertEqual(len(get_agents(self.tmp_dir)), len(self.update_handler.agents))
        return

    def test_load_agents_does_not_reload(self):
        self.prepare_agents()

        self.update_handler._load_agents()
        agents = self.update_handler.agents

        self.update_handler._load_agents()
        self.assertEqual(agents, self.update_handler.agents)
        return

    def test_load_agents_sorts(self):
        self.prepare_agents()
        self.update_handler._load_agents()

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version
        return

    def test_purge_agents(self):
        self.prepare_agents()
        self.update_handler._load_agents()

        # Ensure at least three agents initially exist
        self.assertTrue(2 < len(self.update_handler.agents))

        # Purge every other agent
        kept_agents = self.update_handler.agents[1::2]
        purged_agents = self.update_handler.agents[::2]

        # Reload and assert only the kept agents remain on disk
        self.update_handler.agents = kept_agents
        self.update_handler._purge_agents()
        self.update_handler._load_agents()
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
        return

    def _test_run_latest(self, mock_child=None, mock_time=None):
        if mock_child is None:
            mock_child = ChildMock()
        if mock_time is None:
            mock_time = TimeMock()

        with patch('subprocess.Popen', return_value=mock_child) as mock_popen:
            with patch('time.time', side_effect=mock_time.time):
                with patch('time.sleep', return_value=mock_time.sleep):
                    self.update_handler.run_latest()
                    self.assertEqual(1, mock_popen.call_count)

                    return mock_popen.call_args

    def test_run_latest(self):
        self.prepare_agents()

        agent = self.update_handler.get_latest_agent()
        args, kwargs = self._test_run_latest()
        cmds = shlex.split(agent.get_agent_cmd())
        if cmds[0].lower() == "python":
            cmds[0] = get_python_cmd()

        self.assertEqual(args[0], cmds)
        self.assertEqual(True, 'cwd' in kwargs)
        self.assertEqual(agent.get_agent_dir(), kwargs['cwd'])
        return

    def test_run_latest_polls_and_waits_for_success(self):
        mock_child = ChildMock(return_value=None)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/3)
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(2, mock_child.poll.call_count)
        self.assertEqual(1, mock_child.wait.call_count)
        return

    def test_run_latest_polling_stops_at_success(self):
        mock_child = ChildMock(return_value=0)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/3)
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(1, mock_child.poll.call_count)
        self.assertEqual(0, mock_child.wait.call_count)
        return

    def test_run_latest_polling_stops_at_failure(self):
        mock_child = ChildMock(return_value=42)
        mock_time = TimeMock()
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(1, mock_child.poll.call_count)
        self.assertEqual(0, mock_child.wait.call_count)
        self.assertEqual(2, mock_time.time_call_count)
        return

    def test_run_latest_defaults_to_current(self):
        self.assertEqual(None, self.update_handler.get_latest_agent())

        args, kwargs = self._test_run_latest()

        self.assertEqual(args[0], [get_python_cmd(), "-u", sys.argv[0], "-run-exthandlers"])
        self.assertEqual(True, 'cwd' in kwargs)
        self.assertEqual(os.getcwd(), kwargs['cwd'])
        return

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
        return

    def test_run_latest_nonzero_code_marks_failures(self):
        # logger.add_logger_appender(logger.AppenderType.STDOUT)
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        self._test_run_latest(mock_child=ChildMock(return_value=1))

        self.assertTrue(latest_agent.is_available)
        self.assertNotEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)
        return

    def test_run_latest_exception_blacklists(self):
        # logger.add_logger_appender(logger.AppenderType.STDOUT)
        self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        self._test_run_latest(mock_child=ChildMock(side_effect=Exception("Force blacklisting")))

        self.assertFalse(latest_agent.is_available)
        self.assertTrue(latest_agent.error.is_blacklisted)
        self.assertNotEqual(0.0, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)
        return

    @patch('signal.signal')
    def test_run_latest_captures_signals(self, mock_signal):
        self._test_run_latest()
        self.assertEqual(1, mock_signal.call_count)
        return

    @patch('signal.signal')
    def test_run_latest_creates_only_one_signal_handler(self, mock_signal):
        self.update_handler.signal_handler = "Not None"
        self._test_run_latest()
        self.assertEqual(0, mock_signal.call_count)
        return

    def _test_run(self, invocations=1, calls=[call.run()], enable_updates=False):
        conf.get_autoupdate_enabled = Mock(return_value=enable_updates)

        # Note:
        # - Python only allows mutations of objects to which a function has
        #   a reference. Incrementing an integer directly changes the
        #   reference. Incrementing an item of a list changes an item to
        #   which the code has a reference.
        #   See http://stackoverflow.com/questions/26408941/python-nested-functions-and-variable-scope
        iterations = [0]
        def iterator(*args, **kwargs):
            iterations[0] += 1
            if iterations[0] >= invocations:
                self.update_handler.running = False
            return

        calls = calls * invocations
        
        with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler') as mock_handler:
            with patch('azurelinuxagent.ga.monitor.get_monitor_handler') as mock_monitor:
                with patch('azurelinuxagent.ga.env.get_env_handler') as mock_env:
                    with patch('time.sleep', side_effect=iterator) as mock_sleep:
                        with patch('sys.exit') as mock_exit:

                            self.update_handler.run()

                            self.assertEqual(1, mock_handler.call_count)
                            self.assertEqual(mock_handler.return_value.method_calls, calls)
                            self.assertEqual(invocations, mock_sleep.call_count)
                            self.assertEqual(1, mock_monitor.call_count)
                            self.assertEqual(1, mock_env.call_count)
                            self.assertEqual(1, mock_exit.call_count)
        return

    def test_run(self):
        self._test_run()
        return

    def test_run_keeps_running(self):
        self._test_run(invocations=15)
        return

    def test_run_stops_if_update_available(self):
        self.update_handler._ensure_latest_agent = Mock(return_value=True)
        self._test_run(invocations=0, calls=[], enable_updates=True)
        return

    def test_set_agents_sets_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])
        self.assertTrue(len(self.update_handler.agents) > 0)
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))
        return

    def test_set_agents_sorts_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version
        return


class ChildMock(Mock):
    def __init__(self, return_value=0, side_effect=None):
        Mock.__init__(self, return_value=return_value, side_effect=side_effect)

        self.poll = Mock(return_value=return_value, side_effect=side_effect)
        self.wait = Mock(return_value=return_value, side_effect=side_effect)
        return


class ProtocolMock(object):
    def __init__(self, family="TestAgent", etag=42, versions=None):
        self.family = family
        self.etag = etag
        self.versions = versions if versions is not None else []
        self.create_manifests()
        self.create_packages()
        return

    def create_manifests(self):
        self.agent_manifests = VMAgentManifestList()
        if len(self.versions) <= 0:
            return

        if self.family is not None:
            manifest = VMAgentManifest(family=self.family)
            for i in range(0,10):
                manifest_uri = "https://nowhere.msft/agent/{0}".format(i)
                manifest.versionsManifestUris.append(VMAgentManifestUri(uri=manifest_uri))
            self.agent_manifests.vmAgentManifests.append(manifest)
        return

    def create_packages(self):
        self.agent_packages = ExtHandlerPackageList()
        if len(self.versions) <= 0:
            return

        for version in self.versions:
            package = ExtHandlerPackage(str(version))
            for i in range(0,5):
                package_uri = "https://nowhere.msft/agent_pkg/{0}".format(i)
                package.uris.append(ExtHandlerPackageUri(uri=package_uri))
            self.agent_packages.versions.append(package)
        return

    def get_protocol(self):
        return self

    def get_vmagent_manifests(self):
        return self.agent_manifests, self.etag

    def get_vmagent_pkgs(self, manifest):
        return self.agent_packages


class ResponseMock(Mock):
    def __init__(self, status=restutil.httpclient.OK, response=None):
        Mock.__init__(self)
        self.status = status
        self.response = response
        return

    def read(self):
        return self.response


class TimeMock(Mock):
    def __init__(self, time_increment=1):
        Mock.__init__(self)
        self.next_time = time.time()
        self.time_call_count = 0
        self.time_increment = time_increment

        self.sleep = Mock(return_value=0)
        return

    def time(self):
        self.time_call_count += 1
        current_time = self.next_time
        self.next_time += self.time_increment
        return current_time


if __name__ == '__main__':
    unittest.main()
