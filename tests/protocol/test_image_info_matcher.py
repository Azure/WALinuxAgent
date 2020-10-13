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
# Requires Python 2.6+ and Openssl 1.0+

from azurelinuxagent.common.protocol.imds import ImageInfoMatcher
import unittest # pylint: disable=wrong-import-order


class TestImageInfoMatcher(unittest.TestCase):
    def test_image_does_not_exist(self):
        doc = '{}'

        test_subject = ImageInfoMatcher(doc)
        self.assertFalse(test_subject.is_match("Red Hat", "RHEL", "6.3", ""))

    def test_image_exists_by_sku(self):
        doc = '''{
            "CANONICAL": {
                "UBUNTUSERVER": {
                    "16.04-LTS": { "Match": ".*" }
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)
        self.assertTrue(test_subject.is_match("Canonical", "UbuntuServer", "16.04-LTS", ""))
        self.assertTrue(test_subject.is_match("Canonical", "UbuntuServer", "16.04-LTS", "16.04.201805090"))

        self.assertFalse(test_subject.is_match("Canonical", "UbuntuServer", "14.04.0-LTS", "16.04.201805090"))

    def test_image_exists_by_version(self):
        doc = '''{
            "REDHAT": {
                "RHEL": {
                    "Minimum": "6.3"
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)
        self.assertFalse(test_subject.is_match("RedHat", "RHEL", "6.1", ""))
        self.assertFalse(test_subject.is_match("RedHat", "RHEL", "6.2", ""))

        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "6.3", ""))
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "6.4", ""))
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "6.5", ""))
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "7.0", ""))
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "7.1", ""))

    def test_image_exists_by_version01(self):
        """
        Test case to ensure the matcher exhaustively searches all cases.

        REDHAT/RHEL have a SKU >= 6.3 is less precise than
        REDHAT/RHEL/7-LVM have a any version.

        Both should return a successful match.
        """
        doc = '''{
            "REDHAT": {
                "RHEL": { 
                    "Minimum": "6.3", 
                    "7-LVM": { "Match": ".*" }
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)

        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "6.3", ""))
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "7-LVM", ""))

    def test_ignores_case(self):
        doc = '''{
            "CANONICAL": {
                "UBUNTUSERVER": {
                    "16.04-LTS": { "Match": ".*" }
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)
        self.assertTrue(test_subject.is_match("canonical", "ubuntuserver", "16.04-lts", ""))
        self.assertFalse(test_subject.is_match("canonical", "ubuntuserver", "14.04.0-lts", "16.04.201805090"))

    def test_list_operator(self):
        doc = '''{
            "CANONICAL": {
                "UBUNTUSERVER": {
                    "List": [ "14.04.0-LTS", "14.04.1-LTS" ]
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)
        self.assertTrue(test_subject.is_match("Canonical", "UbuntuServer", "14.04.0-LTS", ""))
        self.assertTrue(test_subject.is_match("Canonical", "UbuntuServer", "14.04.1-LTS", ""))

        self.assertFalse(test_subject.is_match("Canonical", "UbuntuServer", "22.04-LTS", ""))

    def test_invalid_version(self):
        doc = '''{
            "REDHAT": {
                "RHEL": {
                    "Minimum": "6.3"
                }
            }
        }'''

        test_subject = ImageInfoMatcher(doc)
        self.assertFalse(test_subject.is_match("RedHat", "RHEL", "16.04-LTS", ""))

        # This is *expected* behavior as opposed to desirable.  The specification is
        # controlled by the agent, so there is no reason to use these values, but if
        # one does this is expected behavior.
        #
        # FlexibleVersion chops off all leading zeros.
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", "6.04", ""))
        # FlexibleVersion coerces everything to a string
        self.assertTrue(test_subject.is_match("RedHat", "RHEL", 6.04, ""))


if __name__ == '__main__':
    unittest.main()
