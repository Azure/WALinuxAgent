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
import importlib.util
import json

from pathlib import Path
from typing import Any, Dict, List, Type

from tests_e2e.scenarios.lib.agent_test import AgentTest


class TestSuiteDescription(object):
    """
    Description of the test suite loaded from its JSON file.
    """
    name: str
    tests: List[Type[AgentTest]]


class AgentTestLoader(object):
    """
    Loads the description of a set of test suites
    """
    def __init__(self, test_source_directory: Path):
        """
        The test_source_directory parameter must be the root directory of the end-to-end tests (".../WALinuxAgent/tests_e2e")
        """
        self._root: Path = test_source_directory/"scenarios"

    def load(self, test_suites: str) -> List[TestSuiteDescription]:
        """
        Loads the specified 'test_suites', which are given as a string of comma-separated suite names or a JSON description
        of a single test_suite.

        When given as a comma-separated list, each item must correspond to the name of the JSON files describing s suite (those
         files are located under the .../WALinuxAgent/tests_e2e/scenarios/testsuites directory). For example,
         if test_suites == "agent_bvt, fast-track" then this method will load files agent_bvt.json and fast-track.json.

         When given as a JSON string, the value must correspond to the description a single test suite, for example

            {
              "name": "AgentBvt",

              "tests": [
                "bvts/extension_operations.py",
                "bvts/run_command.py",
                "bvts/vm_access.py"
              ]
            }
        """
        # Attempt to parse 'test_suites' as the JSON description for a single suite
        try:
            return [self._load_test_suite(json.loads(test_suites))]
        except json.decoder.JSONDecodeError:
            pass

        # Else, it should be a comma-separated list of description files
        description_files: List[Path] = [self._root/"testsuites"/f"{t.strip()}.json" for t in test_suites.split(',')]
        return [self._load_test_suite(AgentTestLoader._load_file(s)) for s in description_files]

    def _load_test_suite(self, test_suite: Dict[str, Any]) -> TestSuiteDescription:
        """
        Creates a TestSuiteDescription from its JSON representation, which has been loaded by JSON.loads and is passed
        to this method as a dictionary
        """
        suite = TestSuiteDescription()
        suite.name = test_suite["name"]
        suite.tests = []
        for source_file in [self._root/"tests"/t for t in test_suite["tests"]]:
            suite.tests.extend(AgentTestLoader._load_tests(source_file))
        return suite

    @staticmethod
    def _load_tests(source_file: Path) -> List[Type[AgentTest]]:
        """
        Takes a 'source_file', which must be a Python module, and returns a list of all the classes derived from AgentTest.
        """
        spec = importlib.util.spec_from_file_location(f"tests_e2e.scenarios.{source_file.name}", str(source_file))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # return all the classes in the module that are subclasses of AgentTest but are not AgentTest itself.
        return [v for v in module.__dict__.values() if isinstance(v, type) and issubclass(v, AgentTest) and v != AgentTest]

    @staticmethod
    def _load_file(file: Path):
        """Helper to load a JSON file"""
        try:
            with file.open() as f:
                return json.load(f)
        except Exception as e:
            raise Exception(f"Can't load {file}: {e}")


