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
# Requires Python 2.6+ and Openssl 1.0+
#

def get_events_from_mock(mock):
    """
    Extracts the telemetry events from the call_args_list of a mock for one of the azurelinuxagent.common.event.{info,warn,error} functions.
    Those functions have a signature similar to "def info(op, fmt, *args)". Events are returned as an array of (operation, formatted message) tuples.
    """
    return [(args[0], args[1].format(*args[2:])) for args, _ in mock.call_args_list]

