# Copyright Microsoft Corporation
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

import io
import unittest

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.osutil.systemd import is_systemd_run_failure


class TestSystemd(unittest.TestCase):

    def test_is_systemd_run_failure_should_recognize_missing_units_with_or_without_scope_suffix(self):
        unit_name = "enable_29af77ef-2b7a-4d3b-b9ed-6c3a8960bf92"
        for suffix in ("", ".scope"):
            message = ustr("Failed to start transient scope unit: Unit {0}{1} not found.\n").format(unit_name, suffix)
            for stderr in (message, io.BytesIO(message.encode("utf-8"))):
                self.assertTrue(is_systemd_run_failure(unit_name, stderr), message)

    def test_is_systemd_run_failure_should_recognize_errors_without_unit_name(self):
        message = ustr("Failed to connect to bus: No such file or directory")
        for stderr in (message, io.BytesIO(message.encode("utf-8"))):
            self.assertTrue(is_systemd_run_failure("enable_test", stderr))

    def test_is_systemd_run_failure_should_not_classify_extension_errors_as_systemd_failures(self):
        for suffix in ("", ".scope"):
            message = ustr("Running scope as unit: enable_test{0}\nExtension failed\n").format(suffix)
            for stderr in (message, io.BytesIO(message.encode("utf-8"))):
                self.assertFalse(is_systemd_run_failure("enable_test", stderr), message)


if __name__ == '__main__':
    unittest.main()
