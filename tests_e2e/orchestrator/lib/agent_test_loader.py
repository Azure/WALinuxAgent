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
import re
# E0401: Unable to import 'yaml' (import-error)
import yaml  # pylint: disable=E0401

from pathlib import Path
from typing import Any, Dict, List, Type

import tests_e2e
from tests_e2e.tests.lib.agent_test import AgentTest


class TestInfo(object):
    """
    Description of a test
    """
    # The class that implements the test
    test_class: Type[AgentTest]
    # If True, an error in the test blocks the execution of the test suite (defaults to False)
    blocks_suite: bool

    @property
    def name(self) -> str:
        return self.test_class.__name__

    def __str__(self):
        return self.name


class TestSuiteInfo(object):
    """
    Description of a test suite
    """
    # The name of the test suite
    name: str
    # The tests that comprise the suite
    tests: List[TestInfo]
    # Images or image sets (as defined in images.yml) on which the suite must run.
    images: List[str]
    # The location (region) on which the suite must run; if empty, the suite can run on any location
    location: str
    # Whether this suite must run on its own test VM
    owns_vm: bool
    # Customization for the ARM template used when creating the test VM
    template: str

    def __str__(self):
        return self.name


class VmImageInfo(object):
    # The URN of the image (publisher, offer, version separated by spaces)
    urn: str
    # Indicates that the image is available only on those locations. If empty, the image should be available in all locations
    locations: Dict[str, List[str]]
    # Indicates that the image is available only for those VM sizes. If empty, the image should be available for all VM sizes
    vm_sizes: List[str]

    def __str__(self):
        return self.urn


class AgentTestLoader(object):
    """
    Loads a given set of test suites from the YAML configuration files.
    """
    def __init__(self, test_suites: str, cloud: str):
        """
        Loads the specified 'test_suites', which are given as a string of comma-separated suite names or a YAML description
        of a single test_suite.

        The 'cloud' parameter indicates the cloud on which the tests will run. It is used to validate any restrictions on the test suite and/or
        images location.

        When given as a comma-separated list, each item must correspond to the name of the YAML files describing s suite (those
        files are located under the .../WALinuxAgent/tests_e2e/test_suites directory). For example, if test_suites == "agent_bvt, fast_track"
        then this method will load files agent_bvt.yml and fast_track.yml.

        When given as a YAML string, the value must correspond to the description a single test suite, for example

            name: "AgentBvt"
            tests:
              - "bvts/extension_operations.py"
              - "bvts/run_command.py"
              - "bvts/vm_access.py"
        """
        self.__test_suites: List[TestSuiteInfo] = self._load_test_suites(test_suites)
        self.__cloud: str = cloud
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

    RANDOM_IMAGES_RE = re.compile(r"random\((?P<image>[^,]+)(\s*,\s*(?P<count>\d+))?\)")

    def _validate(self):
        """
        Performs some basic validations on the data loaded from the YAML description files
        """
        for suite in self.test_suites:
            # Validate that the images the suite must run on are in images.yml
            for image in suite.images:
                match = AgentTestLoader.RANDOM_IMAGES_RE.match(image)
                if match is not None:
                    image = match.group('image')
                if image not in self.images:
                    raise Exception(f"Invalid image reference in test suite {suite.name}: Can't find {image} in images.yml")

            # If the suite specifies a location, validate that the images it uses are available in that location
            if suite.location != '':
                for suite_image in suite.images:
                    for image in self.images[suite_image]:
                        # If the image has a location restriction, validate that it is available on the location the suite must run on
                        if image.locations:
                            locations = image.locations.get(self.__cloud)
                            if locations is not None and not any(suite.location in l for l in locations):
                                raise Exception(f"Test suite {suite.name} must be executed in {suite.location}, but <{image.urn}> is not available in that location")

    @staticmethod
    def _load_test_suites(test_suites: str) -> List[TestSuiteInfo]:
        #
        # Attempt to parse 'test_suites' as the YML description of a single suite
        #
        parsed = yaml.safe_load(test_suites)

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
        return [AgentTestLoader._load_test_suite(f) for f in description_files]

    @staticmethod
    def _load_test_suite(description_file: Path) -> TestSuiteInfo:
        """
        Loads the description of a TestSuite from its YAML file.

        A test suite has 5 properties: name, tests, images, location, and owns_vm. For example:

            name: "AgentBvt"
            tests:
              - "bvts/extension_operations.py"
              - "bvts/run_command.py"
              - "bvts/vm_access.py"
            images: "endorsed"
            location: "eastuseaup"
            owns_vm: true

        * name     - A string used to identify the test suite
        * tests    - A list of the tests in the suite. Each test can be specified by a string (the path for its source code relative to
                     WALinuxAgent/tests_e2e/tests), or a dictionary with two items:
                        * source: the path for its source code relative to WALinuxAgent/tests_e2e/tests
                        * blocks_suite: [Optional; boolean] If True, a failure on the test will stop execution of the test suite (i.e. the
                          rest of the tests in the suite will not be executed). By default, a failure on a test does not stop execution of
                          the test suite.
        * images   - A string, or a list of strings, specifying the images on which the test suite must be executed. Each value
                     can be the name of a single image (e.g."ubuntu_2004"), or the name of an image set (e.g. "endorsed"). The
                     names for images and image sets are defined in WALinuxAgent/tests_e2e/tests_suites/images.yml.
        * location - [Optional; string] If given, the test suite must be executed on that location. If not specified,
                     or set to an empty string, the test suite will be executed in the default location. This is useful
                     for test suites that exercise a feature that is enabled only in certain regions.
        * owns_vm - [Optional; boolean] By default all suites in a test run are executed on the same test VMs; if this
                    value is set to True, new test VMs will be created and will be used exclusively for this test suite.
                    This is useful for suites that modify the test VMs in such a way that the setup may cause problems
                    in other test suites (for example, some tests targeted to the HGAP block internet access in order to
                    force the agent to use the HGAP).

        """
        test_suite: Dict[str, Any] = AgentTestLoader._load_file(description_file)

        if any([test_suite.get(p) is None for p in ["name", "tests", "images"]]):
            raise Exception(f"Invalid test suite: {description_file}. 'name', 'tests', and 'images' are required properties")

        test_suite_info = TestSuiteInfo()

        test_suite_info.name = test_suite["name"]

        test_suite_info.tests = []
        for test in test_suite["tests"]:
            test_info = TestInfo()
            if isinstance(test, str):
                test_info.test_class = AgentTestLoader._load_test_class(test)
                test_info.blocks_suite = False
            else:
                test_info.test_class = AgentTestLoader._load_test_class(test["source"])
                test_info.blocks_suite = test.get("blocks_suite", False)
            test_suite_info.tests.append(test_info)

        images = test_suite["images"]
        if isinstance(images, str):
            test_suite_info.images = [images]
        else:
            test_suite_info.images = images

        test_suite_info.location = test_suite.get("location")
        if test_suite_info.location is None:
            test_suite_info.location = ""

        test_suite_info.owns_vm = "owns_vm" in test_suite and test_suite["owns_vm"]

        test_suite_info.template = test_suite.get("template", "")

        return test_suite_info

    @staticmethod
    def _load_test_class(relative_path: str) -> Type[AgentTest]:
        """
        Loads an AgentTest from its source code file, which is given as a path relative to WALinuxAgent/tests_e2e/tests.
        """
        full_path: Path = AgentTestLoader._SOURCE_CODE_ROOT/"tests"/relative_path
        spec = importlib.util.spec_from_file_location(f"tests_e2e.tests.{relative_path.replace('/', '.').replace('.py', '')}", str(full_path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # return all the classes in the module that are subclasses of AgentTest but are not AgentTest itself.
        matches = [v for v in module.__dict__.values() if isinstance(v, type) and issubclass(v, AgentTest) and v != AgentTest]
        if len(matches) != 1:
            raise Exception(f"Error in {full_path} (each test file must contain exactly one class derived from AgentTest)")
        return matches[0]

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
                i.locations = {}
                i.vm_sizes = []
            else:
                if "urn" not in description:
                    raise Exception(f"Image {name} is missing the 'urn' property: {description}")
                i.urn = description["urn"]
                i.locations = description["locations"] if "locations" in description else {}
                i.vm_sizes = description["vm_sizes"] if "vm_sizes" in description else []
                for cloud in i.locations.keys():
                    if cloud not in ["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"]:
                        raise Exception(f"Invalid cloud {cloud} for image {name} in images.yml")

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
