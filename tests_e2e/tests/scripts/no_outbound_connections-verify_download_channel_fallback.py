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
# Verifies the download channel fallback behavior on a vm with no outbound connections.
#
import re

from assertpy import assert_that

from tests_e2e.tests.lib.agent_log import AgentLog
from tests_e2e.tests.lib.logging import log


def main():
    # 2026-02-20T22:39:22.691020Z INFO ExtHandler ExtHandler Downloading artifacts profile blob
    # 2026-02-20T22:39:27.714015Z WARNING ExtHandler ExtHandler Fetch failed: [HttpError] [HTTP Failed] GET https://md-hdd-nqxfsnnvnjr3.z27.blob.storage.azure.net/$system/lisa-maddieford-20260220-223218-252-e0-n0.49e33a82-9f6e-4482-86a3-0db71c338ebc.vmSettings -- IOError timed out -- 1 attempts made
    # 2026-02-20T22:39:27.740385Z INFO ExtHandler ExtHandler Default channel changed to HostGAPlugin channel.
    # 2026-02-20T22:39:30.733714Z INFO ExtHandler ExtHandler ProcessExtensionsGoalState started [incarnation_1 channel: WireServer source: Fabric activity: 1082ed79-bbc7-4925-a932-aefe84bca6e9 correlation 2ad608f9-327b-4b2a-8673-6b40ca7ee6e7 created: 2026-02-20T22:33:22.800011Z]
    # Patterns to match
    downloading_vmap = re.compile(r"Downloading artifacts profile blob")                        # This is the artifact download we expect to see the channel change happen on
    fetch_failed_on_direct_pattern = re.compile(r"Fetch failed:.* 1 attempts made")              # There should only be one attempt on the Direct channel before falling back to HostGAPlugin
    default_channel_pattern = re.compile(r"Default channel changed to HostGAPlugin channel")    # The agent should log that it is changing the default channel to HostGAPlugin
    process_extensions_pattern = re.compile(r"ProcessExtensionsGoalState started")              # The agent should switch channels before executing any extensions

    # Track the match timestamps
    found = []

    agentlog = AgentLog()
    for record in agentlog.read():
        # We only care about logs from the ExtHandler
        if record.thread != "ExtHandler" and record.prefix != "ExtHandler":
            continue
        if len(found) == 0 and downloading_vmap.search(record.text):
            found.append(record.timestamp)
            log.info("Found log indicating VMAP download started:\n\t{0}".format(record.text))
        elif len(found) == 1 and fetch_failed_on_direct_pattern.search(record.text):
            found.append(record.timestamp)
            log.info("Found log indicating download failed on Direct channel after 1 attempt:\n\t{0}".format(record.text))
        elif len(found) == 2 and default_channel_pattern.search(record.text):
            found.append(record.timestamp)
            log.info("Found log indicating default channel was changed to HostGAPlugin:\n\t{0}".format(record.text))
        elif len(found) == 3 and process_extensions_pattern.search(record.text):
            found.append(record.timestamp)
            log.info("Found log indicating that the Agent started processing extensions:\n\t{0}".format(record.text))
            break

    assert_that(len(found) == 4).is_true().described_as(
        "The agent log should show that the download failed on the Direct channel after 1 attempt, that the default "
        "channel was changed to HostGAPlugin, and that the Agent started processing extensions (in that order), "
        "but it does not"
    )
    failed_download_duration = (found[1] - found[0]).total_seconds()
    assert_that(failed_download_duration < 6).is_true().described_as("The direct download request should fail fast")


if __name__ == "__main__":
    main()