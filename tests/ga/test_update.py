# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

from __future__ import print_function

import tempfile
import unittest

from azurelinuxagent.common.protocol.hostplugin import *
from azurelinuxagent.common.protocol.metadata import *
from azurelinuxagent.common.protocol.wire import *
from azurelinuxagent.ga.update import *
from tests.tools import AgentTestCase, call, data_dir, DEFAULT, patch, load_bin_data, load_data, Mock, MagicMock


NO_ERROR = {
    "last_failure" : 0.0,
    "failure_count" : 0,
    "was_fatal" : False
}

FATAL_ERROR = {
    "last_failure" : 42.42,
    "failure_count" : 2,
    "was_fatal" : True
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

    def agent_bin(self, version, suffix):
        return "bin/{0}-{1}{2}.egg".format(AGENT_NAME, version, suffix)

    def rename_agent_bin(self, path, src_v, dst_v):
        src_bin = glob.glob(os.path.join(path, self.agent_bin(src_v, '*')))[0]
        dst_bin = os.path.join(path, self.agent_bin(dst_v, ''))
        shutil.move(src_bin, dst_bin)
    
    def agents(self):
        return [GuestAgent(path=path) for path in self.agent_dirs()]

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
            err = GuestAgentError(path.name)
            err.load()
            return err

    def copy_agents(self, *agents):
        if len(agents) <= 0:
            agents = get_agent_pkgs()
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
        self.copy_agents(get_agent_pkgs()[0])
        self.expand_agents()

        versions = self.agent_versions()
        src_v = FlexibleVersion(str(versions[0]))

        from_path = self.agent_dir(src_v)
        dst_v = FlexibleVersion(str(version))
        to_path = self.agent_dir(dst_v)

        if from_path != to_path:
            shutil.move(from_path + ".zip", to_path + ".zip")
            shutil.move(from_path, to_path)
            self.rename_agent_bin(to_path, src_v, dst_v)
        return

    def prepare_agents(self,
                       count=20,
                       is_available=True):

        # Ensure the test data is copied over
        agent_count = self.agent_count()
        if agent_count <= 0:
            self.copy_agents(get_agent_pkgs()[0])
            self.expand_agents()
            count -= 1

        # Determine the most recent agent version
        versions = self.agent_versions()
        src_v = FlexibleVersion(str(versions[0]))

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

    def replicate_agents(self,
                         count=5,
                         src_v=AGENT_VERSION,
                         is_available=True,
                         increment=1):
        from_path = self.agent_dir(src_v)
        dst_v = FlexibleVersion(str(src_v))
        for i in range(0, count):
            dst_v += increment
            to_path = self.agent_dir(dst_v)
            shutil.copyfile(from_path + ".zip", to_path + ".zip")
            shutil.copytree(from_path, to_path)
            self.rename_agent_bin(to_path, src_v, dst_v)
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

        for i in range(0, MAX_FAILURE):
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
        self.copy_agents(get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, get_agent_name())

    def test_creation(self):
        self.assertRaises(UpdateError, GuestAgent, "A very bad file name")
        n = "{0}-a.bad.version".format(AGENT_NAME)
        self.assertRaises(UpdateError, GuestAgent, n)

        self.expand_agents()

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
        self.assertFalse(agent.is_blacklisted)
        self.assertTrue(agent.is_available)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    def test_clear_error(self, mock_downloaded):
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
    def test_is_available(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)

        self.assertFalse(agent.is_available)
        agent._unpack()
        self.assertTrue(agent.is_available)

        agent.mark_failure(is_fatal=True)
        self.assertFalse(agent.is_available)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_is_blacklisted(self, mock_loaded, mock_downloaded):
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
    def test_resource_gone_error_not_blacklisted(self, mock_loaded, mock_downloaded):
        try:
            mock_downloaded.side_effect = ResourceGoneError()
            agent = GuestAgent(path=self.agent_path)
            self.assertFalse(agent.is_blacklisted)
        except ResourceGoneError:
            pass
        except:
            self.fail("Exception was not expected!")

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_ioerror_not_blacklisted(self, mock_loaded, mock_downloaded):
        try:
            mock_downloaded.side_effect = IOError()
            agent = GuestAgent(path=self.agent_path)
            self.assertFalse(agent.is_blacklisted)
        except IOError:
            pass
        except:
            self.fail("Exception was not expected!")

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_is_downloaded(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(agent.is_downloaded)
        agent._unpack()
        self.assertTrue(agent.is_downloaded)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_mark_failure(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)

        agent.mark_failure()
        self.assertEqual(1, agent.error.failure_count)

        agent.mark_failure(is_fatal=True)
        self.assertEqual(2, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_unpack(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isdir(agent.get_agent_dir()))
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_unpack_fail(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        os.remove(agent.get_agent_pkg_path())
        self.assertRaises(UpdateError, agent._unpack)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        agent._unpack()
        agent._load_manifest()
        self.assertEqual(agent.manifest.get_enable_command(),
                         agent.get_agent_cmd())

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_missing(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        os.remove(agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, agent._load_manifest)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_is_empty(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, agent._load_manifest)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    def test_load_manifest_is_malformed(self, mock_loaded, mock_downloaded):
        agent = GuestAgent(path=self.agent_path)
        self.assertFalse(os.path.isdir(agent.get_agent_dir()))
        agent._unpack()
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:
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
    def test_download(self, mock_http_get, mock_loaded, mock_downloaded):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        mock_http_get.return_value= ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)
        agent._download()

        self.assertTrue(os.path.isfile(agent.get_agent_pkg_path()))

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    def test_download_fail(self, mock_http_get, mock_loaded, mock_downloaded):
        self.remove_agents()
        self.assertFalse(os.path.isdir(self.agent_path))

        mock_http_get.return_value= ResponseMock(status=restutil.httpclient.SERVICE_UNAVAILABLE)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertRaises(UpdateError, agent._download)
        self.assertFalse(os.path.isfile(agent.get_agent_pkg_path()))
        self.assertFalse(agent.is_downloaded)

    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_downloaded")
    @patch("azurelinuxagent.ga.update.GuestAgent._ensure_loaded")
    @patch("azurelinuxagent.ga.update.restutil.http_get")
    @patch("azurelinuxagent.ga.update.restutil.http_post")
    def test_download_fallback(self, mock_http_post, mock_http_get, mock_loaded, mock_downloaded):
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

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri(uri=ext_uri))
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
            a, k = mock_http_get.call_args_list[3]
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

        agent_pkg = load_bin_data(os.path.join("ga", get_agent_file_name()))
        mock_http_get.return_value= ResponseMock(response=agent_pkg)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))
        self.assertTrue(agent.is_downloaded)

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

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack", side_effect=UpdateError)
    def test_ensure_downloaded_unpack_fails(self, mock_unpack, mock_download):
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest", side_effect=UpdateError)
    def test_ensure_downloaded_load_manifest_fails(self, mock_manifest, mock_unpack, mock_download):
        self.assertFalse(os.path.isdir(self.agent_path))

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
        agent = GuestAgent(pkg=pkg)

        self.assertEqual(1, agent.error.failure_count)
        self.assertTrue(agent.error.was_fatal)
        self.assertTrue(agent.is_blacklisted)

    @patch("azurelinuxagent.ga.update.GuestAgent._download")
    @patch("azurelinuxagent.ga.update.GuestAgent._unpack")
    @patch("azurelinuxagent.ga.update.GuestAgent._load_manifest")
    def test_ensure_download_skips_blacklisted(self, mock_manifest, mock_unpack, mock_download):
        agent = GuestAgent(path=self.agent_path)
        self.assertEqual(0, mock_download.call_count)

        agent.clear_error()
        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)

        pkg = ExtHandlerPackage(version=str(get_agent_version()))
        pkg.uris.append(ExtHandlerPackageUri())
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
        self.update_handler.protocol_util = Mock()

    def test_creation(self):
        self.assertTrue(self.update_handler.running)

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
        except Exception as e:
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
            def iterator(*args, **kwargs):
                iterations[0] += 1
                return iterations[0] < invocations

            mock_util.check_pid_alive = Mock(side_effect=iterator)

            pid_files = self.update_handler._get_pid_files()
            self.assertEqual(pid_count, len(pid_files))

            with patch('os.getpid', return_value=42):
                with patch('time.sleep', return_value=None) as mock_sleep:
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
                                        interval=3*GOAL_STATE_INTERVAL,
                                        pid_count=1)
            self.assertEqual(3, calls)
            self.assertEqual(2, sleeps)
            self.assertEqual(1, mock_kill.call_count)

    @patch('azurelinuxagent.ga.update.datetime')
    def test_ensure_partition_assigned(self, mock_time):
        path = os.path.join(conf.get_lib_dir(), AGENT_PARTITION_FILE)
        mock_time.utcnow = Mock()

        self.assertFalse(os.path.exists(path))

        for n in range(0,99):
            mock_time.utcnow.return_value = Mock(microsecond=n* 10000)

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
        self.assertEqual(len(get_agents(self.tmp_dir)), len(self.update_handler.agents))

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

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_host_plugin')
    def test_get_host_plugin_returns_none_otherwise(self, mock_get_host):
        protocol = MetadataProtocol()
        host = self.update_handler._get_host_plugin(protocol=protocol)
        mock_get_host.assert_not_called()
        self.assertEqual(None, host)

    def test_get_latest_agent(self):
        latest_version = self.prepare_agents()

        latest_agent = self.update_handler.get_latest_agent()
        self.assertEqual(len(get_agents(self.tmp_dir)), len(self.update_handler.agents))
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

        latest_version = self.prepare_agents(count=self.agent_count()+1, is_available=False)
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
            fileutil.write_file(os.path.join(self.tmp_dir, str(n)+"_waagent.pid"), ustr(n+1))
        pid_files = self.update_handler._get_pid_files()
        self.assertEqual(1250, len(pid_files))

        pid_dir, pid_name, pid_re = self.update_handler._get_pid_parts()
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
    def test_is_version_available_rejects(self, mock_current):
        self.prepare_agents(is_available=True)
        self.update_handler.agents = self.agents()

        self.update_handler.agents[0].mark_failure(is_fatal=True)
        self.assertFalse(self.update_handler._is_version_eligible(self.agents()[0].version))

    @patch("azurelinuxagent.ga.update.is_current_agent_installed", return_value=True)
    def test_is_version_available_accepts_current(self, mock_current):
        self.update_handler.agents = []
        self.assertTrue(self.update_handler._is_version_eligible(CURRENT_VERSION))

    @patch("azurelinuxagent.ga.update.is_current_agent_installed", return_value=False)
    def test_is_version_available_rejects_by_default(self, mock_current):
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

        with patch('subprocess.Popen', return_value=mock_child) as mock_popen:
            with patch('time.time', side_effect=mock_time.time):
                with patch('time.sleep', side_effect=mock_time.sleep):
                    self.update_handler.run_latest(child_args=child_args)
                    self.assertEqual(1, mock_popen.call_count)

                    return mock_popen.call_args

    def test_run_latest(self):
        self.prepare_agents()

        agent = self.update_handler.get_latest_agent()
        args, kwargs = self._test_run_latest()
        args = args[0]
        cmds = textutil.safe_shlex_split(agent.get_agent_cmd())
        if cmds[0].lower() == "python":
            cmds[0] = get_python_cmd()

        self.assertEqual(args, cmds)
        self.assertTrue(len(args) > 1)
        self.assertTrue(args[0].startswith("python"))
        self.assertEqual("-run-exthandlers", args[len(args)-1])
        self.assertEqual(True, 'cwd' in kwargs)
        self.assertEqual(agent.get_agent_dir(), kwargs['cwd'])
        self.assertEqual(False, '\x00' in cmds[0])

    def test_run_latest_passes_child_args(self):
        self.prepare_agents()

        agent = self.update_handler.get_latest_agent()
        args, kwargs = self._test_run_latest(child_args="AnArgument")
        args = args[0]

        self.assertTrue(len(args) > 1)
        self.assertTrue(args[0].startswith("python"))
        self.assertEqual("AnArgument", args[len(args)-1])

    def test_run_latest_polls_and_waits_for_success(self):
        mock_child = ChildMock(return_value=None)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/3)
        self._test_run_latest(mock_child=mock_child, mock_time=mock_time)
        self.assertEqual(2, mock_child.poll.call_count)
        self.assertEqual(1, mock_child.wait.call_count)

    def test_run_latest_polling_stops_at_success(self):
        mock_child = ChildMock(return_value=0)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/3)
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
        mock_child = ChildMock(return_value=0)
        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/2)
        self._test_run_latest(mock_time=mock_time)
        self.assertEqual(1, mock_time.sleep_interval)

    def test_run_latest_polls_every_second_if_installed_not_latest(self):
        self.prepare_agents()

        mock_time = TimeMock(time_increment=CHILD_HEALTH_INTERVAL/2)
        self._test_run_latest(mock_time=mock_time)
        self.assertEqual(1, mock_time.sleep_interval)

    def test_run_latest_defaults_to_current(self):
        self.assertEqual(None, self.update_handler.get_latest_agent())

        args, kwargs = self._test_run_latest()

        self.assertEqual(args[0], [get_python_cmd(), "-u", sys.argv[0], "-run-exthandlers"])
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
            self.update_handler.running = False
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

    def _test_run(self, invocations=1, calls=[call.run()], enable_updates=False, sleep_interval=(3,)):
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

        fileutil.write_file(conf.get_agent_pid_file_path(), ustr(42))

        with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler') as mock_handler:
            with patch('azurelinuxagent.ga.remoteaccess.get_remote_access_handler') as mock_ra_handler:
                with patch('azurelinuxagent.ga.monitor.get_monitor_handler') as mock_monitor:
                    with patch('azurelinuxagent.ga.env.get_env_handler') as mock_env:
                        with patch('time.sleep', side_effect=iterator) as mock_sleep:
                            with patch('sys.exit') as mock_exit:
                                if isinstance(os.getppid, MagicMock):
                                    self.update_handler.run()
                                else:
                                    with patch('os.getppid', return_value=42):
                                        self.update_handler.run()

                                self.assertEqual(1, mock_handler.call_count)
                                self.assertEqual(mock_handler.return_value.method_calls, calls)
                                self.assertEqual(1, mock_ra_handler.call_count)
                                self.assertEqual(mock_ra_handler.return_value.method_calls, calls)
                                self.assertEqual(invocations, mock_sleep.call_count)
                                if invocations > 0:
                                    self.assertEqual(sleep_interval, mock_sleep.call_args[0])
                                self.assertEqual(1, mock_monitor.call_count)
                                self.assertEqual(1, mock_env.call_count)
                                self.assertEqual(1, mock_exit.call_count)

    def test_run(self):
        self._test_run()

    def test_run_keeps_running(self):
        self._test_run(invocations=15, calls=[call.run()]*15)

    def test_run_stops_if_update_available(self):
        self.update_handler._upgrade_available = Mock(return_value=True)
        self._test_run(invocations=0, calls=[], enable_updates=True)

    def test_run_stops_if_orphaned(self):
        with patch('os.getppid', return_value=1):
            self._test_run(invocations=0, calls=[], enable_updates=True)

    def test_run_clears_sentinel_on_successful_exit(self):
        self._test_run()
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_run_leaves_sentinel_on_unsuccessful_exit(self):
        self.update_handler._upgrade_available = Mock(side_effect=Exception)
        self._test_run(invocations=0, calls=[], enable_updates=True)
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
        self.assertFalse(self.update_handler.running)
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_shutdown_ignores_missing_sentinel_file(self):
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))
        self.update_handler._shutdown()
        self.assertFalse(self.update_handler.running)
        self.assertFalse(os.path.isfile(self.update_handler._sentinel_file_path()))

    def test_shutdown_ignores_exceptions(self):
        self.update_handler._set_sentinel()

        try:
            with patch("os.remove", side_effect=Exception):
                self.update_handler._shutdown()
        except Exception as e:
            self.assertTrue(False, "Unexpected exception")

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

        return self.update_handler._upgrade_available(base_version=base_version)

    def test_upgrade_available_returns_true_on_first_use(self):
        self.assertTrue(self._test_upgrade_available())

    def test_upgrade_available_handles_missing_family(self):
        extensions_config = ExtensionsConfig(load_data("wire/ext_conf_missing_family.xml"))
        protocol = ProtocolMock()
        protocol.family = "Prod"
        protocol.agent_manifests = extensions_config.vmagent_manifests
        self.update_handler.protocol_util = protocol
        with patch('azurelinuxagent.common.logger.warn') as mock_logger:
            with patch('tests.ga.test_update.ProtocolMock.get_vmagent_pkgs', side_effect=ProtocolError):
                self.assertFalse(self.update_handler._upgrade_available(base_version=CURRENT_VERSION))
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
            fileutil.write_file(os.path.join(self.tmp_dir, str(n)+"_waagent.pid"), ustr(n+1))
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

    @patch('azurelinuxagent.common.protocol.wire.WireClient.get_goal_state',
           return_value=GoalState(load_data('wire/goal_state.xml')))
    def test_package_filter_for_agent_manifest(self, _):

        protocol = WireProtocol('12.34.56.78')
        extension_config = ExtensionsConfig(load_data('wire/ext_conf.xml'))
        agent_manifest = extension_config.vmagent_manifests.vmAgentManifests[0]

        # has agent versions 13, 14
        ga_manifest_1 = ExtensionManifest(load_data('wire/ga_manifest_1.xml'))

        # has agent versions 13, 14, 15
        ga_manifest_2 = ExtensionManifest(load_data('wire/ga_manifest_2.xml'))

        goal_state = protocol.client.get_goal_state()
        disk_cache = os.path.join(conf.get_lib_dir(),
                                  AGENTS_MANIFEST_FILE_NAME.format(
                                      agent_manifest.family,
                                      goal_state.incarnation))

        self.assertFalse(os.path.exists(disk_cache))
        self.assertTrue(ga_manifest_1.allowed_versions is None)

        with patch(
                'azurelinuxagent.common.protocol.wire.WireClient'
                '.get_gafamily_manifest',
                return_value=ga_manifest_1):

            pkg_list_1 = protocol.get_vmagent_pkgs(agent_manifest)
            self.assertTrue(pkg_list_1 is not None)
            self.assertTrue(len(pkg_list_1.versions) == 2)
            self.assertTrue(pkg_list_1.versions[0].version == '2.2.13')
            self.assertTrue(pkg_list_1.versions[0].uris[0].uri == 'url1_13')
            self.assertTrue(pkg_list_1.versions[1].version == '2.2.14')
            self.assertTrue(pkg_list_1.versions[1].uris[0].uri == 'url1_14')

        self.assertTrue(os.path.exists(disk_cache))

        with patch(
                'azurelinuxagent.common.protocol.wire.WireClient'
                '.get_gafamily_manifest',
                return_value=ga_manifest_2):

            pkg_list_2 = protocol.get_vmagent_pkgs(agent_manifest)
            self.assertTrue(pkg_list_2 is not None)
            self.assertTrue(len(pkg_list_2.versions) == 2)
            self.assertTrue(pkg_list_2.versions[0].version == '2.2.13')
            self.assertTrue(pkg_list_2.versions[0].uris[0].uri == 'url2_13')
            self.assertTrue(pkg_list_2.versions[1].version == '2.2.14')
            self.assertTrue(pkg_list_2.versions[1].uris[0].uri == 'url2_14')
            # does not contain 2.2.15

        self.assertTrue(os.path.exists(disk_cache))
        self.assertTrue(ga_manifest_2.allowed_versions is not None)
        self.assertTrue(len(ga_manifest_2.allowed_versions) == 2)
        self.assertTrue(ga_manifest_2.allowed_versions[0] == '2.2.13')
        self.assertTrue(ga_manifest_2.allowed_versions[1] == '2.2.14')

    @patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False)
    def test_update_happens_when_extensions_disabled(self, _):
        """
        Although the extension enabled config will not get checked
        before an update is found, this test attempts to ensure that
        behavior never changes.
        """
        self.update_handler._upgrade_available = Mock(return_value=True)
        self._test_run(invocations=0, calls=[], enable_updates=True, sleep_interval=(300,))

    @patch('azurelinuxagent.common.conf.get_extensions_enabled', return_value=False)
    def test_interval_changes_when_extensions_disabled(self, _):
        """
        When extension processing is disabled, the goal state interval should be larger.
        """
        self.update_handler._upgrade_available = Mock(return_value=False)
        self._test_run(invocations=15, calls=[call.run()] * 15, sleep_interval=(300,))


class MonitorThreadTest(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        self.event_patch = patch('azurelinuxagent.common.event.add_event')
        self.update_handler = get_update_handler()
        self.update_handler.protocol_util = Mock()

    def _test_run(self, invocations=1):
        iterations = [0]
        def iterator(*args, **kwargs):
            iterations[0] += 1
            if iterations[0] >= invocations:
                self.update_handler.running = False
            return

        with patch('os.getpid', return_value=42):
            with patch.object(UpdateHandler, '_is_orphaned') as mock_is_orphaned:
                mock_is_orphaned.__get__ = Mock(return_value=False)
                with patch('azurelinuxagent.ga.exthandlers.get_exthandlers_handler') as mock_handler:
                    with patch('azurelinuxagent.ga.remoteaccess.get_remote_access_handler') as mock_ra_handler:
                        with patch('time.sleep', side_effect=iterator) as mock_sleep:
                            with patch('sys.exit') as mock_exit:
                                self.update_handler.run()

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_start_threads(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_monitor_thread = MagicMock()
        mock_monitor_thread.run = MagicMock()
        mock_monitor.return_value = mock_monitor_thread

        mock_env_thread = MagicMock()
        mock_env_thread.run = MagicMock()
        mock_env.return_value = mock_env_thread

        self._test_run(invocations=0)
        self.assertEqual(1, mock_monitor.call_count)
        self.assertEqual(1, mock_monitor_thread.run.call_count)
        self.assertEqual(1, mock_env.call_count)
        self.assertEqual(1, mock_env_thread.run.call_count)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_check_if_monitor_thread_is_alive(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_monitor_thread = MagicMock()
        mock_monitor_thread.run = MagicMock()
        mock_monitor_thread.is_alive = MagicMock(return_value=True)
        mock_monitor_thread.start = MagicMock()
        mock_monitor.return_value = mock_monitor_thread

        self._test_run(invocations=0)
        self.assertEqual(1, mock_monitor.call_count)
        self.assertEqual(1, mock_monitor_thread.run.call_count)
        self.assertEqual(1, mock_monitor_thread.is_alive.call_count)
        self.assertEqual(0, mock_monitor_thread.start.call_count)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_check_if_env_thread_is_alive(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_env_thread = MagicMock()
        mock_env_thread.run = MagicMock()
        mock_env_thread.is_alive = MagicMock(return_value=True)
        mock_env_thread.start = MagicMock()
        mock_env.return_value = mock_env_thread

        self._test_run(invocations=1)
        self.assertEqual(1, mock_env.call_count)
        self.assertEqual(1, mock_env_thread.run.call_count)
        self.assertEqual(1, mock_env_thread.is_alive.call_count)
        self.assertEqual(0, mock_env_thread.start.call_count)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_restart_monitor_thread_if_not_alive(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_monitor_thread = MagicMock()
        mock_monitor_thread.run = MagicMock()
        mock_monitor_thread.is_alive = MagicMock(return_value=False)
        mock_monitor_thread.start = MagicMock()
        mock_monitor.return_value = mock_monitor_thread

        self._test_run(invocations=1)
        self.assertEqual(1, mock_monitor.call_count)
        self.assertEqual(1, mock_monitor_thread.run.call_count)
        self.assertEqual(1, mock_monitor_thread.is_alive.call_count)
        self.assertEqual(1, mock_monitor_thread.start.call_count)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_restart_env_thread_if_not_alive(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_env_thread = MagicMock()
        mock_env_thread.run = MagicMock()
        mock_env_thread.is_alive = MagicMock(return_value=False)
        mock_env_thread.start = MagicMock()
        mock_env.return_value = mock_env_thread

        self._test_run(invocations=1)
        self.assertEqual(1, mock_env.call_count)
        self.assertEqual(1, mock_env_thread.run.call_count)
        self.assertEqual(1, mock_env_thread.is_alive.call_count)
        self.assertEqual(1, mock_env_thread.start.call_count)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_restart_monitor_thread(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_monitor_thread = MagicMock()
        mock_monitor_thread.run = MagicMock()
        mock_monitor_thread.is_alive = MagicMock(return_value=False)
        mock_monitor_thread.start = MagicMock()
        mock_monitor.return_value = mock_monitor_thread

        self._test_run(invocations=0)
        self.assertEqual(True, mock_monitor.called)
        self.assertEqual(True, mock_monitor_thread.run.called)
        self.assertEqual(True, mock_monitor_thread.is_alive.called)
        self.assertEqual(True, mock_monitor_thread.start.called)

    @patch('azurelinuxagent.ga.monitor.get_monitor_handler')
    @patch('azurelinuxagent.ga.env.get_env_handler')
    def test_restart_env_thread(self, mock_env, mock_monitor):
        self.assertTrue(self.update_handler.running)

        mock_env_thread = MagicMock()
        mock_env_thread.run = MagicMock()
        mock_env_thread.is_alive = MagicMock(return_value=False)
        mock_env_thread.start = MagicMock()
        mock_env.return_value = mock_env_thread

        self._test_run(invocations=0)
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
            "get_vmagent_manifests" : 0,
            "get_vmagent_pkgs" : 0,
            "update_goal_state" : 0
        }
        self.goal_state_is_stale = False
        self.etag = etag
        self.versions = versions if versions is not None else []
        self.create_manifests()
        self.create_packages()

    def emulate_stale_goal_state(self):
        self.goal_state_is_stale = True

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

    def get_protocol(self):
        return self

    def get_vmagent_manifests(self):
        self.call_counts["get_vmagent_manifests"] += 1
        if self.goal_state_is_stale:
            self.goal_state_is_stale = False
            raise ResourceGoneError()
        return self.agent_manifests, self.etag

    def get_vmagent_pkgs(self, manifest):
        self.call_counts["get_vmagent_pkgs"] += 1
        if self.goal_state_is_stale:
            self.goal_state_is_stale = False
            raise ResourceGoneError()
        return self.agent_packages

    def update_goal_state(self, forced=False):
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


if __name__ == '__main__':
    unittest.main()
