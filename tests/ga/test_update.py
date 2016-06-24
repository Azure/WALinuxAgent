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
    "last_failure" : None,
    "failure_count" : 0,
    "was_fatal" : False
}

WITH_ERROR = {
    "last_failure" : 42.42,
    "failure_count" : 2,
    "was_fatal" : False
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
        v = [FlexibleVersion(AGENT_NAME_PATTERN.match(a).group(1)) for a in self.agent_dirs()]
        v.sort(reverse=True)
        return v

    def copy_agents(self, *agents):
        if len(agents) <= 0:
            agents = get_agent_pkgs()
        for agent in agents:
            fileutil.copy_file(agent, to_dir=self.tmp_dir)
        return

    def expand_agents(self):
        for agent in self.agent_pkgs():
            zipfile.ZipFile(agent).extractall(os.path.join(self.tmp_dir))
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
    def get_error_file(self, error_data=NO_ERROR):
        fp = tempfile.NamedTemporaryFile(mode="w")
        json.dump(error_data if error_data is not None else NO_ERROR, fp)
        fp.seek(0)
        return fp

    def create_error(self, error_data=NO_ERROR):
        with self.get_error_file(error_data) as path:
            return GuestAgentError(path.name)

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


class TestGuestAgent(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.copy_agents(get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, get_agent_name())
        self.agent = GuestAgent(path=self.agent_path)
        return

    def test_creation(self):
        self.assertRaises(UpdateError, GuestAgent, "A very bad file name")
        n = "{0}-a.bad.version".format(AGENT_NAME)
        self.assertRaises(UpdateError, GuestAgent, n)

        self.assertNotEqual(None, self.agent)
        self.assertEqual(get_agent_name(), self.agent.name)
        self.assertEqual(get_agent_version(), self.agent.version)

        self.assertEqual(self.agent_path, self.agent.get_agent_dir())

        path = os.path.join(self.agent_path, AGENT_MANIFEST_FILE)
        self.assertEqual(path, self.agent.get_agent_manifest_path())

        path = os.path.join(self.agent_path, self.agent.manifest.get_enable_command())
        self.assertEqual(path, self.agent.get_agent_bin())

        self.assertEqual(
            os.path.join(self.agent_path, AGENT_ERROR_FILE),
            self.agent.get_agent_error_file())

        path = ".".join(
            (os.path.join(conf.get_lib_dir(), get_agent_name()),
            "zip"))
        self.assertEqual(path, self.agent.get_agent_pkg_file())

        self.assertFalse(self.agent.is_downloaded)
        self.assertFalse(self.agent.is_available)
        return

    def test_is_available(self):
        self.assertFalse(self.agent.is_available)
        self.agent._unpack()
        self.assertTrue(self.agent.is_available)
        
        self.agent.mark_failure(is_fatal=True)
        self.assertFalse(self.agent.is_available)
        return

    def test_is_blacklisted(self):
        self.agent._unpack()
        self.assertFalse(self.agent.is_blacklisted)
        self.assertEqual(self.agent.is_blacklisted, self.agent.error.is_blacklisted)
        
        self.agent.mark_failure(is_fatal=True)
        self.assertTrue(self.agent.is_blacklisted)
        self.assertEqual(self.agent.is_blacklisted, self.agent.error.is_blacklisted)
        return

    def test_is_downloaded(self):
        self.assertFalse(self.agent.is_downloaded)
        self.agent._unpack()
        self.assertTrue(self.agent.is_downloaded)
        return

    def test_mark_failure(self):
        self.agent.mark_failure()
        self.assertEqual(1, self.agent.error.failure_count)

        self.agent.mark_failure(is_fatal=True)
        self.assertEqual(2, self.agent.error.failure_count)
        self.assertTrue(self.agent.is_blacklisted)
        return

    def test_unpack(self):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        self.agent._unpack()
        self.assertTrue(os.path.isdir(self.agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(self.agent.get_agent_bin()))
        return

    def test_unpack_fail(self):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        os.remove(self.agent.get_agent_pkg_file())
        self.agent._unpack()
        self.assertTrue(self.agent.is_blacklisted)
        return

    def test_load_manifest_missing(self):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        self.agent._unpack()
        os.remove(self.agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, self.agent._load_manifest)
        return

    def test_load_manifest_is_empty(self):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        self.agent._unpack()
        self.assertTrue(os.path.isfile(self.agent.get_agent_manifest_path()))

        with open(self.agent.get_agent_manifest_path(), "w") as file:
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, self.agent._load_manifest)
        return

    def test_load_manifest_is_malformed(self):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        self.agent._unpack()
        self.assertTrue(os.path.isfile(self.agent.get_agent_manifest_path()))

        with open(self.agent.get_agent_manifest_path(), "w") as file:
            file.write("This is not JSON data")
        self.assertRaises(UpdateError, self.agent._load_manifest)
        return

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download(self, mock_http_get):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        agent_pkg_resp = MagicMock()
        agent_pkg_resp.status = restutil.httpclient.OK
        agent_pkg_resp.read = Mock(return_value=agent_pkg)
        mock_http_get.return_value= agent_pkg_resp

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        self.agent = GuestAgent(pkg=pkg)
        self.agent._download()
        self.assertTrue(os.path.isdir(self.agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(self.agent.get_agent_bin()))
        self.assertTrue(self.agent.is_downloaded)
        return

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download_fail(self, mock_http_get):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))

        agent_pkg_resp = MagicMock()
        agent_pkg_resp.status = restutil.httpclient.SERVICE_UNAVAILABLE
        mock_http_get.return_value= agent_pkg_resp
        
        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        self.agent = GuestAgent(pkg=pkg)
        self.agent._download()
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))
        self.assertFalse(os.path.isfile(self.agent.get_agent_bin()))
        self.assertFalse(self.agent.is_downloaded)
        return

    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_ensure_downloaded(self, mock_http_get):
        self.assertFalse(os.path.isdir(self.agent.get_agent_dir()))

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        agent_pkg_resp = MagicMock()
        agent_pkg_resp.status = restutil.httpclient.OK
        agent_pkg_resp.read = Mock(return_value=agent_pkg)
        mock_http_get.return_value= agent_pkg_resp
        
        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        self.agent = GuestAgent(pkg=pkg)
        self.agent._download()
        self.assertTrue(os.path.isdir(self.agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(self.agent.get_agent_bin()))
        self.assertTrue(self.agent.is_downloaded)
        return


class TestUpdate(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.update_handler = get_update_handler()
        return

    def _test_ensure_latest_agent(
            self,
            protocol=None,
            versions=None):
        
        latest_version = self.prepare_agents()
        if versions is None or len(versions) <= 0:
            versions = [latest_version]

        self.update_handler.protocol_util = Mock(return_value=ProtocolMock)
        etag = self.update_handler.last_etag if self.update_handler.last_etag is not None else 42
        if protocol is None:
            protocol = ProtocolMock(etag=etag, versions=versions)
        self.update_handler.protocol_util = protocol
        conf.get_autoupdate_gafamily = Mock(return_value=protocol.family)

        return self.update_handler._ensure_latest_agent()

    def test_ensure_latest_agent_returns_true_on_first_use(self):
        self.assertEqual(None, self.update_handler.last_etag)
        self.assertTrue(self._test_ensure_latest_agent())
        return

    def test_ensure_latest_agent_ignores_old_agents(self):
        self.prepare_agents()

        old_count = FlexibleVersion(AGENT_VERSION).version[-1]
        old_version = self.agent_versions()[-1]

        self.replicate_agents(src_v=old_version, count=old_count, increment=-1)
        all_count = len(self.agent_versions())

        self.assertTrue(self._test_ensure_latest_agent(versions=self.agent_versions()))
        self.assertEqual(all_count - old_count, len(self.update_handler.agents))
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

    def test_ensure_latest_agent_skips_when_no_new_versions(self):
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

    def _test_run_latest(self, return_value=0, side_effect=None):
        mock_child = Mock()
        mock_child.wait = Mock(return_value=return_value, side_effect=side_effect)
        with patch('sys.exit', return_value=0) as mock_exit:
            with patch('subprocess.Popen', return_value=mock_child) as mock_popen:
                self.update_handler.run_latest()
                self.assertEqual(1, len(mock_popen.mock_calls))
                self.assertEqual(1, len(mock_exit.mock_calls))

                args, kwargs = mock_popen.call_args
                return args[0][0]

    def test_run_latest(self):
        self.prepare_agents()

        self.assertEqual(
            self._test_run_latest(),
            self.update_handler.get_latest_agent().get_agent_bin())
        return

    def test_run_latest_defaults_to_current(self):
        self.assertEqual(None, self.update_handler.get_latest_agent())
        self.assertEqual(
            self._test_run_latest(),
            sys.argv[0])
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
                        self._test_run_latest(side_effect=faux_logger)
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

    def test_run_latest_marks_failures(self):
        # logger.add_logger_appender(logger.AppenderType.STDOUT)
        self.prepare_agents()
        
        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(None, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        # Any non-zero return code marks a failure
        self._test_run_latest(return_value=1)

        self.assertTrue(latest_agent.is_available)
        self.assertNotEqual(None, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)

        # Absence of a return code marks a failure
        self._test_run_latest(return_value=None)

        self.assertTrue(latest_agent.is_available)
        self.assertNotEqual(None, latest_agent.error.last_failure)
        self.assertEqual(2, latest_agent.error.failure_count)
        return

    def test_run_latest_exception_blacklists(self):
        # logger.add_logger_appender(logger.AppenderType.STDOUT)
        self.prepare_agents()
        
        latest_agent = self.update_handler.get_latest_agent()
        self.assertTrue(latest_agent.is_available)
        self.assertEqual(None, latest_agent.error.last_failure)
        self.assertEqual(0, latest_agent.error.failure_count)

        self._test_run_latest(side_effect=Exception("Force blacklisting"))

        self.assertFalse(latest_agent.is_available)
        self.assertTrue(latest_agent.error.is_blacklisted)
        self.assertNotEqual(None, latest_agent.error.last_failure)
        self.assertEqual(1, latest_agent.error.failure_count)
        return

    def _test_run(self, invocations=1, enable_updates=False):
        conf.get_autoupdate_enabled = Mock(return_value=enable_updates)
        
        mock_sleep = _IterationMock(self.update_handler, invocations=invocations)
        with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler') as mock_handler:
            with  patch('time.sleep', new=mock_sleep):
                try:
                    self.update_handler.run()
                except:
                    pass
                self.assertEqual(invocations + 1, len(mock_handler.mock_calls))
                self.assertEqual(invocations, len(mock_sleep.mock_calls))
        return

    def test_run(self):
        self._test_run()
        return

    def test_run_keeps_running(self):
        self._test_run(invocations=15)
        return

    def test_run_stops_if_update_available(self):
        self.update_handler._ensure_latest_agent = Mock(return_value=True)
        with patch('sys.exit', side_effect=Exception("System Exit")) as mock_exit:
            self._test_run(invocations=0, enable_updates=True)
            self.assertEqual(1, len(mock_exit.mock_calls))
        return

    def test_set_agents(self):
        self.prepare_agents()

        self.update_handler._set_agents([GuestAgent(path=path) for path in self.agent_dirs()])
        self.assertEqual(len(self.agent_dirs()), len(self.update_handler.agents))

        v = FlexibleVersion("100000")
        for a in self.update_handler.agents:
            self.assertTrue(v > a.version)
            v = a.version
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


class _IterationMock(object):
    def __init__(self, update_handler, invocations=1):
        self.update_handler = update_handler
        self.invocations = invocations
        self.mock_calls = []
        return
    
    def __call__(self, *args, **kwargs):
        self.mock_calls.append((args, kwargs))
        if len(self.mock_calls) >= self.invocations:
            self.update_handler.running = False
        return


if __name__ == '__main__':
    unittest.main()
