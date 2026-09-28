#!/usr/bin/env pypy3

# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
# This script verifies that the agent sent telemetry about agent package signatures delivered in the goal state,
# and that the telemetry contains the expected versions:
#
#   - For all goal states, the latest two versions in the manifest should have signatures in the goal state.
#     The caller must pass these as --latest-versions.
#   - For RSM goal states, the RSM requested version's signature should also be in the goal state.
#
# Usage:
#   agent_update-check_gs_signature_telemetry.py --latest-versions <v1> <v2>
#   agent_update-check_gs_signature_telemetry.py --latest-versions <v1> <v2> --rsm-requested-version <version>

import argparse
import json
import re

from assertpy import assert_that, fail

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test


def _find_gs_signature_events(agent_log):
    """
    Searches the agent log for goal state signature telemetry events and returns the parsed JSON payloads.
    The agent logs these events with the prefix 'Agent signatures from goal state: ' followed by a JSON object
    containing 'versions_with_signatures', 'created_on_timestamp', 'rsm_requested_version', and 'activity_id'
    fields.
    """
    events = []
    prefix = "Agent signatures from goal state: "
    pattern = re.compile(re.escape(prefix) + r'(\{.*\})')
    for record in agent_log.read():
        match = pattern.search(record.message)
        if match:
            events.append(json.loads(match.group(1)))
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--latest-versions', dest='latest_versions', nargs='+', required=True,
                        help='The latest two manifest versions to check goal state telemetry for')
    parser.add_argument('--rsm-requested-version', dest='rsm_requested_version', required=False,
                        help='The RSM requested version to check goal state telemetry for')
    args, _ = parser.parse_known_args()

    log.info("Checking agent log for goal state signature telemetry events")

    agent_log = AgentLog()
    events = _find_gs_signature_events(agent_log)

    if len(events) == 0:
        fail("Did not find any goal state signature telemetry events in the agent log. "
             "Expected log entries containing 'versions_with_signatures'.")

    log.info("Found %d goal state signature telemetry event(s)", len(events))

    # Verify all events have the expected structure and contain signatures for the latest two manifest versions
    latest_two = args.latest_versions
    log.info("Checking all events for expected structure and manifest versions: %s", latest_two)
    for event in events:
        log.info("Event: %s", json.dumps(event))
        assert_that(event).contains_key("versions_with_signatures", "created_on_timestamp", "activity_id")
        assert_that(event["versions_with_signatures"]).described_as(
            "versions_with_signatures should be a non-empty list").is_not_empty()
        assert_that(event["created_on_timestamp"]).described_as(
            "created_on_timestamp should not be empty").is_not_empty()
        assert_that(event["activity_id"]).described_as(
            "activity_id should not be empty").is_not_empty()
        for version in latest_two:
            if version not in event["versions_with_signatures"]:
                fail("Latest manifest version {0} was not found in 'versions_with_signatures'. "
                     "Latest manifest versions: {1}, Event: {2}".format(
                         version, latest_two, json.dumps(event)))
    log.info("Verified latest manifest versions %s are in all goal state signature events", latest_two)

    # For RSM goal states, verify that ALL events with a matching rsm_requested_version contain the
    # requested version's signature, and that at least one such event exists.
    if args.rsm_requested_version is not None:
        rsm_events = [event for event in events
                       if event.get("rsm_requested_version") == args.rsm_requested_version]

        if len(rsm_events) == 0:
            fail("No goal state signature event found with rsm_requested_version='{0}'. "
                 "Events: {1}".format(args.rsm_requested_version, json.dumps(events)))

        for event in rsm_events:
            if args.rsm_requested_version not in event["versions_with_signatures"]:
                fail("RSM requested version {0} was not found in 'versions_with_signatures' of RSM goal state "
                     "signature event. Event: {1}".format(args.rsm_requested_version, json.dumps(event)))

        log.info("Verified RSM requested version %s signature is in all %d RSM goal state event(s)",
                 args.rsm_requested_version, len(rsm_events))

    log.info("Successfully verified goal state signature telemetry")


run_remote_test(main)
