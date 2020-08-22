# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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


class ThreadHandlerInterface(object):
    """
    Interface for all thread handlers created and maintained by the GuestAgent.
    """

    @staticmethod
    def get_thread_name():
        raise NotImplementedError("get_thread_name() not implemented")

    def run(self):
        raise NotImplementedError("run() not implemented")

    def is_alive(self):
        raise NotImplementedError("is_alive() not implemented")

    def start(self):
        raise NotImplementedError("start() not implemented")

    def stop(self):
        raise NotImplementedError("stop() not implemented")