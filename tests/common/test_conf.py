# Copyright 2017 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp

from azurelinuxagent.common.conf import *
from tests.tools import *


class TestConfigurationProvider(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        # We create a temporary directory here that we use for some tests 
        # as to easily clean up after running we can't use the convenient
        # TemporaryDirectory as it's python 3+ only nor use self.addCleanup
        # (python 2.7+).
        self.temp_dir = mkdtemp()
        return

    def tearDown(self):
        AgentTestCase.tearDown(self)
        rmtree(self.temp_dir)
        return

    def test_load(self):
        content = """# Some comment line
#Commented=With Value
Key=Value
Quoted="Value"
None=None
Switch=y
Integer=123
"""
        conf = ConfigurationProvider()
        conf.load(content)
        self.assertEqual(conf.get("Commented", None), None)
        self.assertEqual(conf.get("Key", None), "Value")
        self.assertEqual(conf.get("Quoted", None), "Value")
        self.assertEqual(conf.get("None", None), None)
        self.assertEqual(conf.get_switch("Switch", False), True)
        self.assertEqual(conf.get_int("Integer", None), 123)
        return

    def test_load_include(self):
        with NamedTemporaryFile() as conf_file:
            conf_file.write(b"Two=Bar\n")
            conf_file.flush()
            content = """One=Foo
include {0}
Three=Baz
""".format(conf_file.name)
            conf = ConfigurationProvider()
            conf.load(content)
        self.assertEqual(conf.get("One", None), "Foo")
        self.assertEqual(conf.get("Two", None), "Bar")
        self.assertEqual(conf.get("Three", None), "Baz")
        return

    def test_load_include_directory(self):
        with open(os.path.join(self.temp_dir, "one.conf"), "w") as f:
            f.write("Two=Bar\n")
        with open(os.path.join(self.temp_dir, "two.conf"), "w") as f:
            f.write("Three=Baz\n")   
        content = """One=Foo
include {0}
Four=Qux
""".format(self.temp_dir)
        conf = ConfigurationProvider()
        conf.load(content)
        self.assertEqual(conf.get("One", None), "Foo")
        self.assertEqual(conf.get("Two", None), "Bar")
        self.assertEqual(conf.get("Three", None), "Baz")
        self.assertEqual(conf.get("Four", None), "Qux")
        return

    def test_load_include_invalid(self):
        content = "include {0}/missing.conf\n".format(self.temp_dir)
        conf = ConfigurationProvider()
        self.assertRaises(AgentConfigError, conf.load, content)
        return
