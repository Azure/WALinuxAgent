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
import yaml

from pathlib import Path
from typing import Any, Dict, List, Type

import tests_e2e
from tests_e2e.tests.lib.agent_test import AgentTest


class TestSuiteInfo(object):
    """
    Description of a test suite
    """
    # The name of the test suite
    name: str
    # The tests that comprise the suite
    tests: List[Type[AgentTest]]
    # An image or image set (as defined in images.yml) specifying the images the suite must run on.
    images: str
    # The location (region) on which the suite must run; if empty, the suite can run on any location
    location: str

    def __str__(self):
        return f"{self.name} {[t.__name__ for t in self.tests]}"


class VmImageInfo(object):
    # The URN of the image (publisher, offer, version separated by spaces)
    urn: str
    # Indicates that the image is available only on those locations. If empty, the image should be available in all locations
    locations: List[str]
    # Indicates that the image is available only for those VM sizes. If empty, the image should be available for all VM sizes
    vm_sizes: List[str]

    def __str__(self):
        return self.urn


class AgentTestLoader(object):
    """
    Loads a given set of test suites from the YAML configuration files.
    """
    def __init__(self, test_suites: str, load_tests: bool = True):
        """
        Loads the specified 'test_suites', which are given as a string of comma-separated suite names or a YAML description
        of a single test_suite.

        When given as a comma-separated list, each item must correspond to the name of the YAML files describing s suite (those
        files are located under the .../WALinuxAgent/tests_e2e/test_suites directory). For example, if test_suites == "agent_bvt, fast-track"
        then this method will load files agent_bvt.yml and fast-track.yml.

        When given as a YAML string, the value must correspond to the description a single test suite, for example

            name: "AgentBvt"
            tests:
              - "bvts/extension_operations.py"
              - "bvts/run_command.py"
              - "bvts/vm_access.py"
        """
        self.__test_suites: List[TestSuiteInfo] = self._load_test_suites(test_suites, load_tests)
        self.__images: Dict[str, List[VmImageInfo]] = self._load_images()
        self._validate()

    _SOURCE_CODE_ROOT: Path = Path(tests_e2e.__path__[0])

    @property
    def test_suites(self) -> List[TestSuiteInfo]:
        return self.__test_suites

    @property
    def images(self) -> Dict[str, List[VmImageInfo]]:
        """
        A dictionary where, for each item, the key is the name of an image or image set and the value is a list of VmImageInfos for
        the corresponding images.
        """
        return self.__images

    def _validate(self):
        """
        Performs some basic validations on the data loaded from the YAML description files
        """
        for suite in self.test_suites:
            # Validate that the images the suite must run on are in images.yml
            if suite.images not in self.images:
                raise Exception(f"Invalid image reference in test suite {suite.name}: Can't find {suite.images} in images.yml")

            # If the suite specifies a location, validate that the images are available in that location
            if suite.location != '':
                if not any(suite.location in i.locations for i in self.images[suite.images]):
                    raise Exception(f"Test suite {suite.name} must be executed in {suite.location}, but no images in {suite.images} are available in that location")

    @staticmethod
    def _load_test_suites(test_suites: str, load_tests: bool) -> List[TestSuiteInfo]:
        #
        # Attempt to parse 'test_suites' as the YML description of a single suite
        #
        try:
            parsed = yaml.safe_load(test_suites)
        except yaml.scanner.ScannerError:  # Looks like YML, but the syntax is not quite right
            raise

        #
        # A comma-separated list (e.g. "foo", "foo, bar", etc.) is valid YAML, but it is parsed as a string. An actual test suite would
        # be parsed as a dictionary. If it is a dict, take is as the YML description of a single test suite
        #
        if isinstance(parsed, dict):
            return [AgentTestLoader._load_test_suite(parsed)]

        #
        # If test_suites is not YML, then it should be a comma-separated list of description files
        #
        description_files: List[Path] = [AgentTestLoader._SOURCE_CODE_ROOT/"test_suites"/f"{t.strip()}.yml" for t in test_suites.split(',')]
        return [AgentTestLoader._load_test_suite(f, load_tests) for f in description_files]

    @staticmethod
    def _load_test_suite(description_file: Path, load_tests: bool) -> TestSuiteInfo:
        """
        Loads the description of a TestSuite from its YAML file. A test suite has 4 properties: name, tests, images, and location.

        For example:

            name: "AgentBvt"
            tests:
              - "bvts/extension_operations.py"
              - "bvts/run_command.py"
              - "bvts/vm_access.py"
            images: "endorsed"
            location: "eastuseaup"

        * name     - A string used to identify the test suite
        * tests    - A list of the tests in the suite. Each test is specified by the path for its source code relative to
                     WALinuxAgent/tests_e2e/tests.
        * images   - A string specifying the images on which the test suite must be executed. The value can be the name
                     of a single image (e.g."ubuntu_2004"), or the name of an image set (e.g. "endorsed"). The names for
                     images and image sets are defined in WALinuxAgent/tests_e2e/tests_suites/images.yml.
        * location - [Optional] A string; if given, the test suite must be executed on that location. If not specified,
                     or set to an empty string, the test suite will be executed in the default location.
        """
        test_suite: Dict[str, Any] = AgentTestLoader._load_file(description_file)

        if any([test_suite.get(p) is None for p in ["name", "tests", "images"]]):
            raise Exception(f"Invalid test suite: {description_file}. 'name', 'tests', and 'images' are required properties")

        test_suite_info = TestSuiteInfo()

        test_suite_info.name = test_suite["name"]

        test_suite_info.tests = []
        if load_tests:
            source_files = [AgentTestLoader._SOURCE_CODE_ROOT/"tests"/t for t in test_suite["tests"]]
            for f in source_files:
                test_suite_info.tests.extend(AgentTestLoader._load_test_classes(f))

        test_suite_info.images = test_suite["images"]

        test_suite_info.location = test_suite.get("location")
        if test_suite_info.location is None:
            test_suite_info.location = ""

        return test_suite_info

    @staticmethod
    def _load_test_classes(source_file: Path) -> List[Type[AgentTest]]:
        """
        Takes a 'source_file', which must be a Python module, and returns a list of all the classes derived from AgentTest.
        """
        spec = importlib.util.spec_from_file_location(f"tests_e2e.tests.{source_file.name}", str(source_file))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # return all the classes in the module that are subclasses of AgentTest but are not AgentTest itself.
        return [v for v in module.__dict__.values() if isinstance(v, type) and issubclass(v, AgentTest) and v != AgentTest]

    @staticmethod
    def _load_images() -> Dict[str, List[VmImageInfo]]:
        """
        Loads images.yml into a dictionary where, for each item, the key is an image or image set and the value is a list of VmImageInfos
        for the corresponding images.

        See the comments in image.yml for a description of the structure of each item.
        """
        image_descriptions = AgentTestLoader._load_file(AgentTestLoader._SOURCE_CODE_ROOT/"test_suites"/"images.yml")
        if "images" not in image_descriptions:
            raise Exception("images.yml is missing the 'images' item")

        images = {}

        # first load the images as 1-item lists
        for name, description in image_descriptions["images"].items():
            i = VmImageInfo()
            if isinstance(description, str):
                i.urn = description
                i.locations = []
                i.vm_sizes = []
            else:
                if "urn" not in description:
                    raise Exception(f"Image {name} is missing the 'urn' property: {description}")
                i.urn = description["urn"]
                i.locations = description["locations"] if "locations" in description else []
                i.vm_sizes = description["vm_sizes"] if "vm_sizes" in description else []
            images[name] = [i]

        # now load the image-sets, mapping them to the images that we just computed
        for image_set_name, image_list in image_descriptions["image-sets"].items():
            # the same name cannot denote an image and an image-set
            if image_set_name in images:
                raise Exception(f"Invalid image-set in images.yml: {image_set_name}. The name is used by an existing image")
            images_in_set = []
            for i in image_list:
                if i not in images:
                    raise Exception(f"Can't find image {i} (referenced by image-set {image_set_name}) in images.yml")
                images_in_set.extend(images[i])
            images[image_set_name] = images_in_set

        return images

    @staticmethod
    def _load_file(file: Path) -> Dict[str, Any]:
        """Helper to load a YML file"""
        try:
            with file.open() as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise Exception(f"Can't load {file}: {e}")
