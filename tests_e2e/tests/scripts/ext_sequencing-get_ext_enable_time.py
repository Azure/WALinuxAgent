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
# Gets the timestamp for when the provided extension was enabled
#

import argparse
import re
import sys
from datetime import datetime

from tests_e2e.tests.lib.agent_log import AgentLog


def main():
    """
    Searches the agent log after the provided timestamp to determine when the agent enabled the provided extension.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--ext", dest='ext', required=True)
    parser.add_argument("--after_time", dest='after_time', required=True)
    args, _ = parser.parse_known_args()

    # Only search the agent log after the provided timestamp: args.after_time
    after_time = datetime.strptime(args.after_time, u'%Y-%m-%d %H:%M:%S')
    # Agent logs for extension enable: 2024-02-09T09:29:08.943529Z INFO ExtHandler [Microsoft.Azure.Extensions.CustomScript-2.1.10] Enable extension: [bin/custom-script-shim enable]
    enable_log_regex = r"\[{0}-[.\d]+\] Enable extension: .*".format(args.ext)

    agent_log = AgentLog()
    try:
        for agent_record in agent_log.read():
            if agent_record.timestamp >= after_time:
                # The agent_record prefix for enable logs is the extension name, for example: [Microsoft.Azure.Extensions.CustomScript-2.1.10]
                if agent_record.prefix:
                    ext_enabled = re.match(enable_log_regex, " ".join([agent_record.prefix, agent_record.message]))

                    if ext_enabled is not None:
                        print(agent_record.when)
                        sys.exit(0)
    except IOError as e:
        print("Error when parsing agent log: {0}".format(str(e)))

    print("Extension {0} was not enabled after {1}".format(args.ext, args.after_time), file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
