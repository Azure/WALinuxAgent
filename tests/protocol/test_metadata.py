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

import json

from azurelinuxagent.common.future import ustr

from azurelinuxagent.common.utils.restutil import httpclient
from azurelinuxagent.common.protocol.metadata import *
from azurelinuxagent.common.protocol.restapi import *

from tests.protocol.mockmetadata import *
from tests.tools import *

class TestMetadataProtocolGetters(AgentTestCase):
    def load_json(self, path):
        return json.loads(ustr(load_data(path)), encoding="utf-8")

    @patch("time.sleep")
    @patch("azurelinuxagent.common.protocol.metadata.restutil")
    def _test_getters(self, test_data, mock_restutil ,_):
        mock_restutil.http_get.side_effect = test_data.mock_http_get

        protocol = MetadataProtocol()
        protocol.detect()
        protocol.get_vminfo()
        protocol.get_certs()
        ext_handlers, etag = protocol.get_ext_handlers()
        for ext_handler in ext_handlers.extHandlers:
            protocol.get_ext_handler_pkgs(ext_handler)

    def test_getters(self, *args):
        test_data = MetadataProtocolData(DATA_FILE)
        self._test_getters(test_data, *args)

    def test_getters_no(self, *args):
        test_data = MetadataProtocolData(DATA_FILE_NO_EXT)
        self._test_getters(test_data, *args)


    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol.update_goal_state")
    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol._get_data")
    def test_get_vmagents_manifests(self, mock_get, mock_update):
        data = self.load_json("metadata/vmagent_manifests.json")
        mock_get.return_value = data, 42

        protocol = MetadataProtocol()
        manifests, etag = protocol.get_vmagent_manifests()

        self.assertEqual(mock_update.call_count, 1)
        self.assertEqual(mock_get.call_count, 1)

        manifests_uri = BASE_URI.format(
            METADATA_ENDPOINT,
            "vmAgentVersions",
            APIVERSION)
        self.assertEqual(mock_get.call_args[0][0], manifests_uri)

        self.assertEqual(etag, 42)
        self.assertNotEqual(None, manifests)
        self.assertEqual(len(manifests.vmAgentManifests), 1)

        manifest = manifests.vmAgentManifests[0]
        self.assertEqual(manifest.family, conf.get_autoupdate_gafamily())
        self.assertEqual(len(manifest.versionsManifestUris), 2)

        # Same etag returns the same data
        data = self.load_json("metadata/vmagent_manifests_invalid1.json")
        mock_get.return_value = data, 42
        next_manifests, etag = protocol.get_vmagent_manifests()

        self.assertEqual(etag, 42)
        self.assertEqual(manifests, next_manifests)

        # New etag returns new data
        mock_get.return_value = data, 43
        self.assertRaises(ProtocolError, protocol.get_vmagent_manifests)

    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol.update_goal_state")
    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol._get_data")
    def test_get_vmagents_manifests_raises(self, mock_get, mock_update):
        data = self.load_json("metadata/vmagent_manifests_invalid1.json")
        mock_get.return_value = data, 42

        protocol = MetadataProtocol()
        self.assertRaises(ProtocolError, protocol.get_vmagent_manifests)

        data = self.load_json("metadata/vmagent_manifests_invalid2.json")
        mock_get.return_value = data, 43
        self.assertRaises(ProtocolError, protocol.get_vmagent_manifests)

    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol.update_goal_state")
    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol._get_data")
    def test_get_vmagent_pkgs(self, mock_get, mock_update):
        data = self.load_json("metadata/vmagent_manifests.json")
        mock_get.return_value = data, 42

        protocol = MetadataProtocol()
        manifests, etag = protocol.get_vmagent_manifests()
        manifest = manifests.vmAgentManifests[0]

        data = self.load_json("metadata/vmagent_manifest1.json")
        mock_get.return_value = data, 42
        pkgs = protocol.get_vmagent_pkgs(manifest)

        self.assertNotEqual(None, pkgs)
        self.assertEqual(len(pkgs.versions), 2)

        for pkg in pkgs.versions:
            self.assertNotEqual(None, pkg.version)
            self.assertTrue(len(pkg.uris) > 0)

            for uri in pkg.uris:
                self.assertTrue(uri.uri.endswith("zip"))

    @patch("azurelinuxagent.common.protocol.metadata.MetadataProtocol._post_data")
    def test_report_event(self, mock_post):
        events = TelemetryEventList()

        data = self.load_json("events/1478123456789000.tld")
        event = TelemetryEvent()
        set_properties("event", event, data)
        events.events.append(event)

        data = self.load_json("events/1478123456789001.tld")
        event = TelemetryEvent()
        set_properties("event", event, data)
        events.events.append(event)

        data = self.load_json("events/1479766858966718.tld")
        event = TelemetryEvent()
        set_properties("event", event, data)
        events.events.append(event)

        protocol = MetadataProtocol()
        protocol.report_event(events)

        events_uri = BASE_URI.format(
            METADATA_ENDPOINT,
            "status/telemetry",
            APIVERSION)

        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(mock_post.call_args[0][0], events_uri)
        self.assertEqual(mock_post.call_args[0][1], get_properties(events))
