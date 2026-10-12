# Copyright 2026 Microsoft Corporation
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

import json

import azurelinuxagent.common.opentelemetry as agent_opentelemetry
from tests.lib.tools import AgentTestCase, Mock

agent_opentelemetry.enable_vendored_packages()

from azurelinuxagent.common.opentelemetry_exporter import (  # noqa: E402
    HostPluginSpanExporter,
    encode_spans_as_otlp_json
)
from opentelemetry.sdk.resources import Resource  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SpanExportResult  # noqa: E402
from opentelemetry.trace import SpanKind, Status, StatusCode  # noqa: E402


class TestOpenTelemetryExporter(AgentTestCase):
    @staticmethod
    def _create_span(name="ProcessExtensionsGoalState"):
        provider = TracerProvider(resource=Resource.create({
            "service.name": "WALinuxAgent",
            "service.version": "2.15.0"
        }))
        tracer = provider.get_tracer("azurelinuxagent.ga.exthandlers", "1.0")
        with tracer.start_as_current_span(
                name,
                kind=SpanKind.CONSUMER,
                attributes={
                    "string": "value",
                    "integer": 42,
                    "boolean": True,
                    "double": 1.5
                }) as span:
            span.add_event("goal-state-received", {"retry": False})
            span.set_status(Status(StatusCode.OK))
        return span

    def test_encode_spans_as_otlp_json_matches_host_contract(self):
        span = self._create_span()

        payload = json.loads(encode_spans_as_otlp_json([span]).decode("utf-8"))

        resource_spans = payload["resourceSpans"][0]
        scope_spans = resource_spans["scopeSpans"][0]
        encoded_span = scope_spans["spans"][0]
        self.assertEqual("azurelinuxagent.ga.exthandlers", scope_spans["scope"]["name"])
        self.assertEqual("ProcessExtensionsGoalState", encoded_span["name"])
        self.assertEqual(5, encoded_span["kind"])
        self.assertEqual(32, len(encoded_span["traceId"]))
        self.assertEqual(16, len(encoded_span["spanId"]))
        self.assertEqual(1, encoded_span["status"]["code"])
        self.assertEqual("goal-state-received", encoded_span["events"][0]["name"])

        attributes = {
            attribute["key"]: attribute["value"]
            for attribute in encoded_span["attributes"]
        }
        self.assertEqual({"stringValue": "value"}, attributes["string"])
        self.assertEqual({"intValue": "42"}, attributes["integer"])
        self.assertEqual({"boolValue": True}, attributes["boolean"])
        self.assertEqual({"doubleValue": 1.5}, attributes["double"])

    def test_export_posts_json_to_host_plugin(self):
        response = Mock()
        response.status = 200
        response.read.return_value = b"{}"
        http_post = Mock(return_value=response)
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            timeout=7,
            http_post=http_post
        )

        result = exporter.export([self._create_span()])

        self.assertEqual(SpanExportResult.SUCCESS, result)
        arguments = http_post.call_args
        self.assertEqual("http://168.63.129.16:32526/traces", arguments[0][0])
        self.assertEqual({"Content-Type": "application/json"}, arguments[1]["headers"])
        self.assertTrue(arguments[1]["redact_data"])
        self.assertEqual(7, arguments[1]["timeout"])
        self.assertEqual(
            "ProcessExtensionsGoalState",
            json.loads(arguments[1]["data"].decode("utf-8"))
            ["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"]
        )

    def test_export_splits_batches_at_host_span_limit(self):
        response = Mock()
        response.status = 200
        response.read.return_value = b"{}"
        http_post = Mock(return_value=response)
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            http_post=http_post
        )
        span = self._create_span()

        result = exporter.export([span] * 65)

        self.assertEqual(SpanExportResult.SUCCESS, result)
        self.assertEqual(2, http_post.call_count)
        sent_counts = []
        for call in http_post.call_args_list:
            payload = json.loads(call[1]["data"].decode("utf-8"))
            sent_counts.append(len(payload["resourceSpans"][0]["scopeSpans"][0]["spans"]))
        self.assertEqual([64, 1], sent_counts)

    def test_export_treats_partial_success_as_delivered(self):
        response = Mock()
        response.status = 200
        response.read.return_value = (
            '{"partialSuccess":{"rejectedSpans":"1","errorMessage":"rejected"}}'
        )
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            http_post=Mock(return_value=response)
        )

        self.assertEqual(
            SpanExportResult.SUCCESS,
            exporter.export([self._create_span()])
        )

    def test_export_splits_batch_after_payload_too_large_response(self):
        too_large = Mock()
        too_large.status = 413
        too_large.read.return_value = b'{"code":8}'
        success = Mock()
        success.status = 200
        success.read.return_value = b"{}"
        http_post = Mock(side_effect=[too_large, success, success])
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            http_post=http_post
        )
        span = self._create_span()

        result = exporter.export([span, span])

        self.assertEqual(SpanExportResult.SUCCESS, result)
        self.assertEqual(3, http_post.call_count)

    def test_export_pauses_after_host_endpoint_not_found(self):
        response = Mock()
        response.status = 404
        response.read.return_value = b'{"code":5}'
        http_post = Mock(return_value=response)
        clock = Mock(return_value=100)
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            http_post=http_post,
            clock=clock
        )
        span = self._create_span()

        self.assertEqual(SpanExportResult.FAILURE, exporter.export([span]))
        self.assertEqual(SpanExportResult.FAILURE, exporter.export([span]))
        self.assertEqual(1, http_post.call_count)

    def test_shutdown_rejects_new_batches(self):
        http_post = Mock()
        exporter = HostPluginSpanExporter(
            host_endpoint="168.63.129.16",
            http_post=http_post
        )

        exporter.shutdown()

        self.assertEqual(
            SpanExportResult.FAILURE,
            exporter.export([self._create_span()])
        )
        http_post.assert_not_called()
