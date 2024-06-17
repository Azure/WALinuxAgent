from tests.lib.tools import AgentTestCase
from azurelinuxagent.ga.policy.policy_engine import PolicyEngine
import unittest
from azurelinuxagent.common.protocol.restapi import ExtensionSettings, Extension
from unittest.mock import patch


class TestPolicyEngine(AgentTestCase):
    """Test the PolicyEngine class."""

    @staticmethod
    def cleanup_engine(self, engine):
        """Helper method to reset singleton."""
        engine._initialized = False
        engine._policy_supported = False
        engine._extension_policy_enabled = False
        engine._engine = None
    def test_get_instance(self):
        """
        Test case to verify the singleton behavior of the policy engine.
        """
        policy_engine1 = PolicyEngine.get_instance()
        policy_engine2 = PolicyEngine.get_instance()
        self.assertIs(policy_engine1, policy_engine2)

    def test_supported_distro(self):
        """
        Test case to verify that policy is enabled when distro is supported.
        """
        try:
            with patch('azurelinuxagent.common.version.get_distro', return_value=['ubuntu', '16.04']), \
                 patch('azurelinuxagent.common.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine.get_instance()
                engine.initialize()
            assert engine.get_extension_policy_enabled() == True
        finally:
            self.cleanup_engine(self, engine)


    def test_unsupported_distro(self):
        """
        Test case to verify that policy is disabled fails when distro is unsupported.
        """
        try:
            with patch('azurelinuxagent.ga.policy.policy_engine.get_distro', return_value=['rhel', '9.0']), \
                 patch('azurelinuxagent.ga.policy.policy_engine.conf.get_extension_policy_enabled', return_value=True):
                engine = PolicyEngine.get_instance()
                # reset singleton attributes
                engine.initialize()
                assert engine.get_extension_policy_enabled() == False
        finally:
            self.cleanup_engine(self, engine)


