#!/usr/bin/env python
#
# Tests for redacted settings
#
# Copyright 2014 Microsoft Corporation
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

import unittest
import Utils.HandlerUtil as Util


class TestRedactedProtectedSettings(unittest.TestCase):

    def test_redacted_protected_settings(self):
        redacted = Util.HandlerUtility.redact_protected_settings(settings_original)
        self.assertIn('"protectedSettings": "*** REDACTED ***"', redacted)
        self.assertIn('"protectedSettingsCertThumbprint": "*** REDACTED ***"', redacted)


settings_original = """\
{
    "runtimeSettings": [{
        "handlerSettings": {
            "protectedSettingsCertThumbprint": "9310D2O49D7216D4A1CEDCE9D8A7CE5DBD7FB7BF",
            "protectedSettings": "MIIC4AYJKoZIhvcNAQcWoIIB0TCDEc0CAQAxggFpMIIBZQIBADBNMDkxNzA1BgoJkiaJk/IsZAEZFidXaW5kb3dzIEF6dXJlIENSUCBDZXJ0aWZpY2F0ZSBHZW5lcmF0b3ICEB8f7DyzHLGjSDLnEWd4YeAwDQYJKoZIhvcNAQEBBQAEggEAiZj2gQtT4MpdTaEH8rUVFB/8Ucc8OxGFWu8VKbIdoHLKp1WcDb7Vlzv6fHLBIccgXGuR1XHTvtlD4QiKpSet341tPPug/R5ZtLSRz1pqtXZdrFcuuSxOa6ib/+la5ukdygcVwkEnmNSQaiipPKyqPH2JsuhmGCdXFiKwCSTrgGE6GyCBtaK9KOf48V/tYXHnDGrS9q5a1gRF5KVI2B26UYSO7V7pXjzYCd/Sp9yGj7Rw3Kqf9Lpix/sPuqWjV6e2XFlD3YxaHSeHVnLI/Bkz2E6Ri8yfPYus52r/mECXPL2YXqY9dGyrlKKIaD9AuzMyvvy1A74a9VBq7zxQQ4adEzBbBgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECDyEf4mRrmWJgDhW4j2nRNTJU4yXxocQm/PhAr39Um7n0pgI2Cn28AabYtsHWjKqr8Al9LX6bKm8cnmnLjqTntphCw==",
            "publicSettings": {}
            }
     }]
}
"""

if __name__ == '__main__':
    unittest.main()
