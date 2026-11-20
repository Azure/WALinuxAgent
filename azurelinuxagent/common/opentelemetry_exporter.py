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
import math
import time

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.protocol.util import get_protocol_util
from azurelinuxagent.common.utils import restutil

from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import format_span_id, format_trace_id


_HOST_PLUGIN_PORT = 32526
_HOST_PLUGIN_TRACES_URI = "http://{0}:{1}/traces"
_MAX_PAYLOAD_BYTES = 256 * 1024
_MAX_SPANS_PER_REQUEST = 64
_UNSUPPORTED_ENDPOINT_COOLDOWN_SECONDS = 5 * 60
_MAX_ATTRIBUTE_KEY_BYTES = 128
_MAX_ATTRIBUTE_VALUE_BYTES = 16 * 1024
_RESERVED_ATTRIBUTE_PREFIX = "guest.reserved."


def _truncate_utf8(value, maximum_bytes):
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore")


def _encode_attribute_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        if math.isfinite(value):
            return {"doubleValue": value}
        return {"stringValue": str(value)}
    if isinstance(value, (tuple, list)):
        value = json.dumps(list(value), separators=(",", ":"), ensure_ascii=False)
    elif not isinstance(value, str):
        value = str(value)
    return {
        "stringValue": _truncate_utf8(value, _MAX_ATTRIBUTE_VALUE_BYTES)
    }


def _encode_attributes(attributes):
    encoded_attributes = []
    if not attributes:
        return encoded_attributes

    for key, value in attributes.items():
        key = str(key)
        if not key or key.startswith(_RESERVED_ATTRIBUTE_PREFIX):
            continue
        if len(key.encode("utf-8")) > _MAX_ATTRIBUTE_KEY_BYTES:
            continue
        encoded_attributes.append({
            "key": key,
            "value": _encode_attribute_value(value)
        })
    return encoded_attributes


def _encode_status(status):
    encoded_status = {"code": status.status_code.value}
    if status.description:
        encoded_status["message"] = _truncate_utf8(
            status.description,
            _MAX_ATTRIBUTE_VALUE_BYTES
        )
    return encoded_status


def _encode_event(event):
    return {
        "name": event.name,
        "timeUnixNano": str(event.timestamp),
        "attributes": _encode_attributes(event.attributes)
    }


def _encode_link(link):
    return {
        "traceId": format_trace_id(link.context.trace_id),
        "spanId": format_span_id(link.context.span_id),
        "attributes": _encode_attributes(link.attributes)
    }


def _encode_span(span):
    span_context = span.get_span_context()
    encoded_span = {
        "traceId": format_trace_id(span_context.trace_id),
        "spanId": format_span_id(span_context.span_id),
        "name": span.name,
        "kind": span.kind.value + 1,
        "startTimeUnixNano": str(span.start_time),
        "endTimeUnixNano": str(span.end_time),
        "attributes": _encode_attributes(span.attributes),
        "status": _encode_status(span.status)
    }
    if span.parent is not None:
        encoded_span["parentSpanId"] = format_span_id(span.parent.span_id)
    if span.events:
        encoded_span["events"] = [_encode_event(event) for event in span.events]
    if span.links:
        encoded_span["links"] = [_encode_link(link) for link in span.links]
    return encoded_span


def _resource_key(resource):
    return tuple(sorted(
        (str(key), json.dumps(_encode_attribute_value(value), sort_keys=True))
        for key, value in resource.attributes.items()
    ))


def _scope_key(scope):
    if scope is None:
        return "", ""
    return scope.name or "", scope.version or ""


def encode_spans_as_otlp_json(spans):
    resource_groups = {}
    resource_order = []

    for span in spans:
        resource_key = _resource_key(span.resource)
        resource_group = resource_groups.get(resource_key)
        if resource_group is None:
            resource_group = {
                "resource": {
                    "attributes": _encode_attributes(span.resource.attributes)
                },
                "scopeSpans": [],
                "_scope_groups": {}
            }
            resource_groups[resource_key] = resource_group
            resource_order.append(resource_group)

        scope_key = _scope_key(span.instrumentation_scope)
        scope_group = resource_group["_scope_groups"].get(scope_key)
        if scope_group is None:
            scope_group = {
                "scope": {
                    "name": scope_key[0],
                    "version": scope_key[1]
                },
                "spans": []
            }
            resource_group["_scope_groups"][scope_key] = scope_group
            resource_group["scopeSpans"].append(scope_group)

        scope_group["spans"].append(_encode_span(span))

    for resource_group in resource_order:
        del resource_group["_scope_groups"]

    return json.dumps(
        {"resourceSpans": resource_order},
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


class HostPluginSpanExporter(SpanExporter):
    def __init__(self, host_endpoint=None, timeout=10, http_post=None, clock=None):
        self._host_endpoint = host_endpoint
        self._timeout = timeout
        self._http_post = http_post or restutil.http_post
        self._clock = clock or time.time
        self._unsupported_until = 0
        self._shutdown = False

    def _get_traces_uri(self):
        endpoint = self._host_endpoint
        if endpoint is None:
            endpoint = get_protocol_util().get_wireserver_endpoint()
        return _HOST_PLUGIN_TRACES_URI.format(endpoint, _HOST_PLUGIN_PORT)

    def _post(self, payload):
        return self._http_post(
            self._get_traces_uri(),
            data=payload,
            headers={"Content-Type": "application/json"},
            max_retry=3,
            retry_codes=[429, 503],
            retry_delay=1,
            throttle_delay=1,
            redact_data=True,
            timeout=self._timeout
        )

    @staticmethod
    def _log_partial_success(response_body):
        try:
            if isinstance(response_body, bytes):
                response_body = response_body.decode("utf-8")
            response = json.loads(response_body)
            partial_success = response.get("partialSuccess")
            if partial_success:
                logger.warn(
                    "HostGAPlugin partially accepted an OpenTelemetry span batch: rejected spans [{0}]",
                    partial_success.get("rejectedSpans", "unknown")
                )
        except (AttributeError, TypeError, ValueError, UnicodeDecodeError):
            logger.warn("HostGAPlugin returned an invalid OpenTelemetry success response")

    def _export_batch(self, spans):
        payload = encode_spans_as_otlp_json(spans)
        if len(payload) > _MAX_PAYLOAD_BYTES:
            if len(spans) == 1:
                logger.warn(
                    "Dropping an OpenTelemetry span because its HostGAPlugin payload exceeds {0} bytes",
                    _MAX_PAYLOAD_BYTES
                )
                return False
            midpoint = len(spans) // 2
            return self._export_batch(spans[:midpoint]) and self._export_batch(spans[midpoint:])

        try:
            response = self._post(payload)
            status = response.status
            response_body = response.read()
        except Exception as error:
            logger.warn(
                "OpenTelemetry export to HostGAPlugin failed: {0}",
                error.__class__.__name__
            )
            return False

        if status == 200:
            self._log_partial_success(response_body)
            return True

        if status == 404:
            self._unsupported_until = self._clock() + _UNSUPPORTED_ENDPOINT_COOLDOWN_SECONDS
            logger.info(
                "HostGAPlugin OpenTelemetry endpoint is unavailable; export is paused for {0} seconds",
                _UNSUPPORTED_ENDPOINT_COOLDOWN_SECONDS
            )
            return False

        if status == 413 and len(spans) > 1:
            midpoint = len(spans) // 2
            return self._export_batch(spans[:midpoint]) and self._export_batch(spans[midpoint:])

        logger.warn(
            "HostGAPlugin OpenTelemetry export failed with HTTP status [{0}]",
            status
        )
        return False

    def export(self, spans):
        if self._shutdown:
            return SpanExportResult.FAILURE
        if self._clock() < self._unsupported_until:
            return SpanExportResult.FAILURE

        spans = list(spans)
        exported = True
        for index in range(0, len(spans), _MAX_SPANS_PER_REQUEST):
            if not self._export_batch(spans[index:index + _MAX_SPANS_PER_REQUEST]):
                exported = False
        return SpanExportResult.SUCCESS if exported else SpanExportResult.FAILURE

    def shutdown(self):
        self._shutdown = True
