import contextlib
import json
import os
import tempfile

from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import UpdateError
from azurelinuxagent.ga.guestagent import GuestAgent, AGENT_MANIFEST_FILE, AGENT_ERROR_FILE, GuestAgentError, \
    MAX_FAILURE, GuestAgentUpdateAttempt
from azurelinuxagent.common.version import AGENT_NAME
from tests.ga.test_update import UpdateTestCase, EMPTY_MANIFEST, WITH_ERROR, NO_ERROR


class TestGuestAgent(UpdateTestCase):
    def setUp(self):
        UpdateTestCase.setUp(self)
        self.copy_agents(self._get_agent_file_path())
        self.agent_path = os.path.join(self.tmp_dir, self._get_agent_name())

    def test_creation(self):
        with self.assertRaises(UpdateError):
            GuestAgent.from_installed_agent("A very bad file name")

        with self.assertRaises(UpdateError):
            GuestAgent.from_installed_agent("{0}-a.bad.version".format(AGENT_NAME))

        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
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

    def test_clear_error(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
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

    def test_is_available(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)

        self.assertTrue(agent.is_available)
        agent.mark_failure(is_fatal=True)
        self.assertFalse(agent.is_available)

    def test_is_blacklisted(self):
        self.expand_agents()

        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertFalse(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

        agent.mark_failure(is_fatal=True)
        self.assertTrue(agent.is_blacklisted)
        self.assertEqual(agent.is_blacklisted, agent.error.is_blacklisted)

    def test_is_downloaded(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(agent.is_downloaded)

    def test_mark_failure(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)

        agent.mark_failure()
        self.assertEqual(1, agent.error.failure_count)

        agent.mark_failure(is_fatal=True)
        self.assertEqual(2, agent.error.failure_count)
        self.assertTrue(agent.is_blacklisted)

    def test_inc_update_attempt_count(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent.inc_update_attempt_count()
        self.assertEqual(1, agent.update_attempt_data.count)

        agent.inc_update_attempt_count()
        self.assertEqual(2, agent.update_attempt_data.count)

    def test_get_update_count(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent.inc_update_attempt_count()
        self.assertEqual(1, agent.get_update_attempt_count())

        agent.inc_update_attempt_count()
        self.assertEqual(2, agent.get_update_attempt_count())

    def test_load_manifest(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent._load_manifest()
        self.assertEqual(agent.manifest.get_enable_command(),
                         agent.get_agent_cmd())

    def test_load_manifest_missing(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        os.remove(agent.get_agent_manifest_path())
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_manifest_is_empty(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            json.dump(EMPTY_MANIFEST, file)
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_manifest_is_malformed(self):
        self.expand_agents()
        agent = GuestAgent.from_installed_agent(self.agent_path)
        self.assertTrue(os.path.isfile(agent.get_agent_manifest_path()))

        with open(agent.get_agent_manifest_path(), "w") as file:  # pylint: disable=redefined-builtin
            file.write("This is not JSON data")
        self.assertRaises(UpdateError, agent._load_manifest)

    def test_load_error(self):
        agent = GuestAgent.from_installed_agent(self.agent_path)
        agent.error = None

        agent._load_error()
        self.assertTrue(agent.error is not None)


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
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}, Reason: {3}".format(
            NO_ERROR["last_failure"],
            NO_ERROR["failure_count"],
            NO_ERROR["was_fatal"],
            NO_ERROR["reason"])
        self.assertEqual(s, str(err))

        err = self.create_error(error_data=WITH_ERROR)
        s = "Last Failure: {0}, Total Failures: {1}, Fatal: {2}, Reason: {3}".format(
            WITH_ERROR["last_failure"],
            WITH_ERROR["failure_count"],
            WITH_ERROR["was_fatal"],
            WITH_ERROR["reason"])
        self.assertEqual(s, str(err))
        return


UPDATE_ATTEMPT = {
    "count": 2
}

NO_ATTEMPT = {
    "count": 0
}


class TestGuestAgentUpdateAttempt(UpdateTestCase):
    @contextlib.contextmanager
    def get_attempt_count_file(self, attempt_count=None):
        if attempt_count is None:
            attempt_count = NO_ATTEMPT
        with tempfile.NamedTemporaryFile(mode="w") as fp:
            json.dump(attempt_count, fp)
            fp.seek(0)
            yield fp

    def test_creation(self):
        self.assertRaises(TypeError, GuestAgentUpdateAttempt)
        self.assertRaises(UpdateError, GuestAgentUpdateAttempt, None)

        with self.get_attempt_count_file(UPDATE_ATTEMPT) as path:
            update_data = GuestAgentUpdateAttempt(path.name)
            update_data.load()
            self.assertEqual(path.name, update_data.path)
        self.assertNotEqual(None, update_data)

        self.assertEqual(UPDATE_ATTEMPT["count"], update_data.count)

    def test_clear(self):
        with self.get_attempt_count_file(UPDATE_ATTEMPT) as path:
            update_data = GuestAgentUpdateAttempt(path.name)
            update_data.load()
            self.assertEqual(path.name, update_data.path)
        self.assertNotEqual(None, update_data)

        update_data.clear()
        self.assertEqual(NO_ATTEMPT["count"], update_data.count)

    def test_save(self):
        with self.get_attempt_count_file(UPDATE_ATTEMPT) as path:
            update_data = GuestAgentUpdateAttempt(path.name)
            update_data.load()
        update_data.inc_count()
        update_data.save()

        with self.get_attempt_count_file(update_data.to_json()) as path:
            new_data = GuestAgentUpdateAttempt(path.name)
            new_data.load()

        self.assertEqual(update_data.count, new_data.count)

    def test_inc_count(self):
        with self.get_attempt_count_file() as path:
            update_data = GuestAgentUpdateAttempt(path.name)
            update_data.load()

        self.assertEqual(0, update_data.count)
        update_data.inc_count()
        self.assertEqual(1, update_data.count)
        update_data.inc_count()
        self.assertEqual(2, update_data.count)
