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

from azurelinuxagent.common.future import BACKSLASH_REPLACE, ustr
from tests.lib.tools import AgentTestCase


class TestBackslashReplace(AgentTestCase):
    def test_it_should_replace_unicode_characters_when_encoding_to_utf8(self):
        self.assertEqual(ustr("\\xc2Hello\\xffWorld!\\xa1"), ustr(b"\xc2Hello\xffWorld!\xa1", encoding='utf-8', errors=BACKSLASH_REPLACE))

    def test_it_should_replace_unicode_characters_when_decoding_from_utf8(self):
        self.assertEqual(ustr("\\xc2Hello\\xffWorld!\\xa1"), b"\xc2Hello\xffWorld!\xa1".decode('utf-8', BACKSLASH_REPLACE))

