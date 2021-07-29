# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

import json
import os

from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import IncompleteGoalStateError
from azurelinuxagent.common.protocol.goal_state import GoalState, ExtensionsConfig
from tests.protocol.mocks import mock_wire_protocol
from tests.protocol import mockwiredata
from tests.protocol.mocks import HttpRequestPredicates
from tests.tools import AgentTestCase, patch

class GoalStateTestCase(HttpRequestPredicates, AgentTestCase):
    def test_fetch_goal_state_should_raise_on_incomplete_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE) as protocol:
            GoalState.fetch_full_goal_state(protocol.client)

            protocol.mock_wire_data.data_files = mockwiredata.DATA_FILE_NOOP_GS
            protocol.mock_wire_data.reload()
            protocol.mock_wire_data.set_incarnation(2)

            with self.assertRaises(IncompleteGoalStateError):
                GoalState.fetch_full_goal_state_if_incarnation_different_than(protocol.client, 1)

    def test_update_goal_state_should_save_goal_state(self):
        with mock_wire_protocol(mockwiredata.DATA_FILE_VM_SETTINGS) as protocol:
            with patch("azurelinuxagent.common.protocol.wire.conf.get_fetch_vm_settings", return_value=True):
                protocol.mock_wire_data.set_incarnation(999)
                protocol.mock_wire_data.set_etag(888)
                protocol.update_goal_state()

        extensions_config_file = os.path.join(conf.get_lib_dir(), "ExtensionsConfig.999.xml")
        vm_settings_file = os.path.join(conf.get_lib_dir(), "VmSettings.888.json")
        expected_files = [
            os.path.join(conf.get_lib_dir(), "GoalState.999.xml"),
            os.path.join(conf.get_lib_dir(), "SharedConfig.xml"),
            os.path.join(conf.get_lib_dir(), "Certificates.xml"),
            os.path.join(conf.get_lib_dir(), "HostingEnvironmentConfig.xml"),
            extensions_config_file,
            vm_settings_file
        ]

        for f in expected_files:
            self.assertTrue(os.path.exists(f), "{0} was not saved".format(f))

        with open(extensions_config_file, "r") as file_:
            extensions_config = ExtensionsConfig(file_.read())
        self.assertEqual(4, len(extensions_config.ext_handlers.extHandlers), "Expected 4 extensions in the test ExtensionsConfig")
        for e in extensions_config.ext_handlers.extHandlers:
            self.assertEqual(e.properties.extensions[0].protectedSettings, "*** REDACTED ***", "The protected settings for {0} were not redacted".format(e.name))

        # TODO: Use azurelinuxagent.common.protocol.ExtensionsGoalState once it implements parsing
        with open(vm_settings_file, "r") as file_:
            vm_settings = json.load(file_)
        extensions = vm_settings["extensionGoalStates"]
        self.assertEqual(4, len(extensions), "Expected 4 extensions in the test vmSettings")
        for e in extensions:
            self.assertEqual(e["settings"][0]["protectedSettings"], "*** REDACTED ***", "The protected settings for {0} were not redacted".format(e["name"]))