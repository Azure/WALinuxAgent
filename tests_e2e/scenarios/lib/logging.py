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
import logging

#
# This module defines a single object, 'log', which test use for logging.
#
# When the test is invoked as part of a LISA test suite, 'log' references the LISA root logger.
# Otherwise, it references a new Logger named 'waagent'.
#

log: logging.Logger = logging.getLogger("lisa")

if not log.hasHandlers():
    log = logging.getLogger("waagent")
    console_handler = logging.StreamHandler()
    log.addHandler(console_handler)

log.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%SZ")
for handler in log.handlers:
    handler.setFormatter(formatter)
