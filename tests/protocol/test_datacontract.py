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

import unittest

from azurelinuxagent.common.datacontract import get_properties, set_properties, DataContract, DataContractList


class SampleDataContract(DataContract): # pylint: disable=too-few-public-methods
    def __init__(self):
        self.foo = None # pylint: disable=blacklisted-name
        self.bar = DataContractList(int) # pylint: disable=blacklisted-name


class TestDataContract(unittest.TestCase):
    def test_get_properties(self):
        obj = SampleDataContract()
        obj.foo = "foo"
        obj.bar.append(1)
        data = get_properties(obj)
        self.assertEqual("foo", data["foo"])
        self.assertEqual(list, type(data["bar"]))

    def test_set_properties(self):
        obj = SampleDataContract()
        data = {
                'foo' : 1,
                'baz': 'a'
        }
        set_properties('sample', obj, data)
        self.assertFalse(hasattr(obj, 'baz'))


if __name__ == '__main__':
    unittest.main()
