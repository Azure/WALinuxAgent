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
#

from tests_e2e.tests.lib.cgroup_helpers import verify_controllers_available
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false


def main():
    # In some systems both may not be mounted or populated immediately after boot. So checking for cpu controller only as we set the cpu limit using cgroups
    log.info("===== Verifying if cgroup controllers are mounted on the system before installing extensions")
    controllers_enabled: bool = retry_if_false(lambda: verify_controllers_available(["cpu"]), delay=120, attempts=7)
    if not controllers_enabled:
        raise Exception("The distro does not have CPU controller enabled.")

    log.info("Verified cpu controller is available")


if __name__ == "__main__":
    main()
