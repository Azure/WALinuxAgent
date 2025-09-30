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
# This script is used to add or delete the DROP rule which drops outbound traffic to HGAP port
#
import argparse

from tests_e2e.tests.lib.firewall_manager import FirewallManager
from tests_e2e.tests.lib.logging import log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', required=True)
    args = parser.parse_args()

    if args.action not in ["add", "delete"]:
        raise Exception("Invalid action. Supported actions are 'add' and 'delete'")

    firewall_manager = FirewallManager.create()

    if args.action == "add":
        # Add drop rule
        firewall_manager.setup_outbound_drop_rule_hgap()
        log.info("Successfully setup outbound drop rule for hgap port")
    else:
        # Delete drop rule
        firewall_manager.delete_outbound_drop_rule_hgap()
        log.info("Successfully deleted outbound drop rule for hgap port")


if __name__ == "__main__":
    main()
