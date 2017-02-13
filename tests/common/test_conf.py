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
include {}
Three=Baz
""".format(conf_file.name)
            conf = ConfigurationProvider()
            conf.load(content)
        self.assertEqual(conf.get("One", None), "Foo")
        self.assertEqual(conf.get("Two", None), "Bar")
        self.assertEqual(conf.get("Three", None), "Baz")
        return

    def test_load_include_directory(self):
        conf_dir = mkdtemp()
        self.addCleanup(rmtree, conf_dir)
        with open(os.path.join(conf_dir, "one.conf"), "w") as f:
            f.write("Two=Bar\n")
        with open(os.path.join(conf_dir, "two.conf"), "w") as f:
            f.write("Three=Baz\n")   
        content = """One=Foo
include {}
Four=Qux
""".format(conf_dir)
        conf = ConfigurationProvider()
        conf.load(content)
        self.assertEqual(conf.get("One", None), "Foo")
        self.assertEqual(conf.get("Two", None), "Bar")
        self.assertEqual(conf.get("Three", None), "Baz")
        self.assertEqual(conf.get("Four", None), "Qux")
        return

    def test_load_include_invalid(self):
        conf_dir = mkdtemp()
        self.addCleanup(rmtree, conf_dir)
        content = "include {}/missing.conf\n".format(conf_dir)
        conf = ConfigurationProvider()
        with self.assertRaises(AgentConfigError):
            conf.load(content)
        return
