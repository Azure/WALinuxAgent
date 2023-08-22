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
import sys

from typing import Callable

from tests_e2e.tests.lib.logging import log

SUCCESS_EXIT_CODE = 0
FAIL_EXIT_CODE = 100
ERROR_EXIT_CODE = 200


def run_remote_test(test_method: Callable[[], None]) -> None:
    """
    Helper function to run a remote test; implements coding conventions for remote tests, e.g. error message goes
    to stderr, test log goes to stdout, etc.
    """
    try:
        test_method()
        log.info("*** PASSED")
    except AssertionError as e:
        print(f"{e}", file=sys.stderr)
        log.error("%s", e)
        sys.exit(FAIL_EXIT_CODE)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        log.exception("*** UNEXPECTED ERROR")
        sys.exit(ERROR_EXIT_CODE)

    sys.exit(SUCCESS_EXIT_CODE)

