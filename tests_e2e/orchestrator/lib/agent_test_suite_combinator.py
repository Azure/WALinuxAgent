# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import logging
import random
import re
import urllib.parse

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

# E0401: Unable to import 'dataclasses_json' (import-error)
from dataclasses_json import dataclass_json  # pylint: disable=E0401

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import schema  # pylint: disable=E0401
from lisa.combinator import Combinator  # pylint: disable=E0401
from lisa.util import field_metadata  # pylint: disable=E0401

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader, VmImageInfo, TestSuiteInfo


@dataclass_json()
@dataclass
class AgentTestSuitesCombinatorSchema(schema.Combinator):
    test_suites: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    cloud: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    location: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    image: str = field(
        default_factory=str, metadata=field_metadata(required=False)
    )
    vm_size: str = field(
        default_factory=str, metadata=field_metadata(required=False)
    )
    vm_name: str = field(
        default_factory=str, metadata=field_metadata(required=False)
    )


class AgentTestSuitesCombinator(Combinator):
    """
    The "agent_test_suites" combinator returns a list of variables that specify the environments (i.e. test VMs) that the agent
    test suites must be executed on:

        * c_env_name: Unique name for the environment, e.g. "0001-com-ubuntu-server-focal-20_04-lts-westus2"
        * c_marketplace_image: e.g. "Canonical UbuntuServer 18.04-LTS latest",
        * c_location: e.g. "westus2",
        * c_vm_size: e.g. "Standard_D2pls_v5"
        * c_vhd: e.g "https://rhel.blob.core.windows.net/images/RHEL_8_Standard-8.3.202006170423.vhd?se=..."
        * c_test_suites: e.g. [AgentBvt, FastTrack]

    (c_marketplace_image, c_location, c_vm_size) and vhd are mutually exclusive and define the environment (i.e. the test VM)
    in which the test will be executed. c_test_suites defines the test suites that should be executed in that
    environment.

    The 'vm_name' runbook parameter can be used to execute the test suites on an existing VM. In that case, the combinator
    generates a single item with these variables:

        * c_env_name: Name for the environment, same as vm_name
        * c_vm_name:  Name of the test VM
        * c_location: Location of the test VM e.g. "westus2",
        * c_test_suites: e.g. [AgentBvt, FastTrack]
    """
    def __init__(self, runbook: AgentTestSuitesCombinatorSchema) -> None:
        super().__init__(runbook)
        if self.runbook.cloud not in self._DEFAULT_LOCATIONS:
            raise Exception(f"Invalid cloud: {self.runbook.cloud}")

        if self.runbook.vm_name != '' and (self.runbook.image != '' or self.runbook.vm_size != ''):
            raise Exception("Invalid runbook parameters: When 'vm_name' is specified, 'image' and 'vm_size' should not be specified.")

        if self.runbook.vm_name != '':
            self._environments = self.create_environment_for_existing_vm()
        else:
            self._environments = self.create_environment_list()
        self._index = 0


    @classmethod
    def type_name(cls) -> str:
        return "agent_test_suites"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return AgentTestSuitesCombinatorSchema

    def _next(self) -> Optional[Dict[str, Any]]:
        result: Optional[Dict[str, Any]] = None
        if self._index < len(self._environments):
            result = self._environments[self._index]
            self._index += 1
        return result

    _DEFAULT_LOCATIONS = {
        "AzureCloud": "westus2",
        "AzureChinaCloud": "chinanorth2",
        "AzureUSGovernment": "usgovarizona",
    }

    _MARKETPLACE_IMAGE_INFORMATION_LOCATIONS = {
        "AzureCloud": "",  # empty indicates the default location used by LISA
        "AzureChinaCloud": "chinanorth2",
        "AzureUSGovernment": "usgovarizona",
    }

    _SHARED_RESOURCE_GROUP_LOCATIONS = {
        "AzureCloud": "",   # empty indicates the default location used by LISA
        "AzureChinaCloud": "chinanorth2",
        "AzureUSGovernment": "usgovarizona",
    }

    def create_environment_for_existing_vm(self) -> List[Dict[str, Any]]:
        loader = AgentTestLoader(self.runbook.test_suites, self.runbook.cloud)

        environment: Dict[str, Any] = {
            "c_env_name": self.runbook.vm_name,
            "c_vm_name": self.runbook.vm_name,
            "c_location": self.runbook.location,
            "c_test_suites": loader.test_suites,
        }

        log: logging.Logger = logging.getLogger("lisa")
        log.info("******** Waagent: Settings for existing VM *****")
        log.info("")
        log.info("Settings for %s:\n%s\n", environment['c_env_name'], self._get_env_settings(environment))
        log.info("")

        return [environment]

    def create_environment_list(self) -> List[Dict[str, Any]]:
        """
        Examines the test_suites specified in the runbook and returns a list of the environments (i.e. test VMs) that need to be
        created in order to execute these suites.

        Note that if the runbook provides an 'image', 'location', or 'vm_size', those values override any values provided in the
        configuration of the test suites.
        """
        environments: List[Dict[str, Any]] = []
        shared_environments: Dict[str, Dict[str, Any]] = {}  # environments shared by multiple test suites

        loader = AgentTestLoader(self.runbook.test_suites, self.runbook.cloud)

        runbook_images = self._get_runbook_images(loader)

        for suite_info in loader.test_suites:
            if len(runbook_images) > 0:
                images_info: List[VmImageInfo] = runbook_images
            else:
                images_info: List[VmImageInfo] = self._get_test_suite_images(suite_info, loader)

            for image in images_info:
                # 'image.urn' can actually be the URL to a VHD if the runbook provided it in the 'image' parameter
                if self._is_vhd(image.urn):
                    c_marketplace_image = ""
                    c_vhd = image.urn
                    image_name = "vhd"
                else:
                    c_marketplace_image = image.urn
                    c_vhd = ""
                    image_name = self._get_image_name(image.urn)

                c_location: str = self._get_location(suite_info, image)
                if c_location is None:
                    continue

                c_vm_size = self._get_vm_size(image)

                # Note: Disabling "W0640: Cell variable 'foo' defined in loop (cell-var-from-loop)". This is a false positive, the closure is OK
                # to use, since create_environment() is called within the same iteration of the loop.
                # pylint: disable=W0640
                def create_environment(c_env_name: str) -> Dict[str, Any]:
                    c_vm_tags = {}
                    if suite_info.template != '':
                        c_vm_tags["templates"] = suite_info.template
                    return {
                        "c_marketplace_image": c_marketplace_image,
                        "c_cloud": self.runbook.cloud,
                        "c_location": c_location,
                        "c_vm_size": c_vm_size,
                        "c_vhd": c_vhd,
                        "c_test_suites": [suite_info],
                        "c_env_name": c_env_name,
                        "c_marketplace_image_information_location": self._MARKETPLACE_IMAGE_INFORMATION_LOCATIONS[self.runbook.cloud],
                        "c_shared_resource_group_location": self._SHARED_RESOURCE_GROUP_LOCATIONS[self.runbook.cloud],
                        "c_vm_tags": c_vm_tags
                    }
                # pylint: enable=W0640

                if suite_info.owns_vm:
                    # create an environment for exclusive use by this suite
                    environments.append(create_environment(f"{image_name}-{suite_info.name}"))
                else:
                    # add this suite to the shared environments
                    key: str = f"{image_name}-{c_location}"
                    env = shared_environments.get(key)
                    if env is not None:
                        env["c_test_suites"].append(suite_info)
                        if suite_info.template != '':
                            vm_tags = env["c_vm_tags"]
                            if "templates" in vm_tags:
                                vm_tags["templates"] += ", " + suite_info.template
                            else:
                                vm_tags["templates"] = suite_info.template
                    else:
                        shared_environments[key] = create_environment(key)

        environments.extend(shared_environments.values())

        if len(environments) == 0:
            raise Exception("No VM images were found to execute the test suites.")

        log: logging.Logger = logging.getLogger("lisa")
        log.info("")
        log.info("******** Waagent: Test Environments *****")
        log.info("")
        for env in environments:
            log.info("Settings for %s:\n%s\n", env['c_env_name'], self._get_env_settings(env))
        log.info("")

        return environments

    def _get_runbook_images(self, loader: AgentTestLoader) -> List[VmImageInfo]:
        """
        Returns the images specified in the runbook, or an empty list if none are specified.
        """
        if self.runbook.image == "":
            return []

        images = loader.images.get(self.runbook.image)
        if images is not None:
            return images

        # If it is not image or image set, it must be a URN or VHD
        if not self._is_urn(self.runbook.image) and not self._is_vhd(self.runbook.image):
            raise Exception(f"The 'image' parameter must be an image, an image set name, a urn, or a vhd: {self.runbook.image}")

        i = VmImageInfo()
        i.urn = self.runbook.image  # Note that this could be a URN or the URI for a VHD
        i.locations = []
        i.vm_sizes = []

        return [i]

    @staticmethod
    def _get_test_suite_images(suite: TestSuiteInfo, loader: AgentTestLoader) -> List[VmImageInfo]:
        """
        Returns the images used by a test suite.

        A test suite may be reference multiple image sets and sets can intersect; this method eliminates any duplicates.
        """
        unique: Dict[str, VmImageInfo] = {}
        for image in suite.images:
            match = AgentTestLoader.RANDOM_IMAGES_RE.match(image)
            if match is None:
                image_list = loader.images[image]
            else:
                count = match.group('count')
                if count is None:
                    count = 1
                matching_images = loader.images[match.group('image_set')].copy()
                random.shuffle(matching_images)
                image_list = matching_images[0:count]
            for i in image_list:
                unique[i.urn] = i
        return [v for k, v in unique.items()]

    def _get_location(self, suite_info: TestSuiteInfo, image: VmImageInfo) -> str:
        """
        Returns the location on which the test VM for the given test suite and image should be created.

        If the image is not available on any location, returns None, to indicate that the test suite should be skipped.
        """
        # If the runbook specified a location, use it.
        if self.runbook.location != "":
            return self.runbook.location

        #  Then try the suite location, if any.
        if suite_info.location != '':
            return suite_info.location

        # If the image has a location restriction, use any location where it is available.
        # However, if it is not available on any location, skip the image (return None)
        if image.locations:
            image_locations = image.locations.get(self.runbook.cloud)
            if image_locations is not None:
                if len(image_locations) == 0:
                    return None
                return image_locations[0]

        # Else use the default.
        return AgentTestSuitesCombinator._DEFAULT_LOCATIONS[self.runbook.cloud]

    def _get_vm_size(self, image: VmImageInfo) -> str:
        """
        Returns the VM size that should be used to create the test VM for the given image.

        If the size is set to an empty string, LISA will choose an appropriate size
        """
        # If the runbook specified a VM size, use it.
        if self.runbook.vm_size != '':
            return self.runbook.vm_size

        #  If the image specifies a list of VM sizes, use any of them.
        if len(image.vm_sizes) > 0:
            return image.vm_sizes[0]

        # Otherwise, set the size to empty and LISA will select an appropriate size.
        return ""

    @staticmethod
    def _get_image_name(urn: str) -> str:
        """
        Creates an image name ("offer-sku") given its URN
        """
        match = AgentTestSuitesCombinator._URN.match(urn)
        if match is None:
            raise Exception(f"Invalid URN: {urn}")
        return f"{match.group('offer')}-{match.group('sku')}"

    @staticmethod
    def _get_env_settings(environment: Dict[str, Any]):
        suite_names = [s.name for s in environment['c_test_suites']]
        return '\n'.join([f"\t{name}: {value if name != 'c_test_suites' else suite_names}" for name, value in environment.items()])

    _URN = re.compile(r"(?P<publisher>[^\s:]+)[\s:](?P<offer>[^\s:]+)[\s:](?P<sku>[^\s:]+)[\s:](?P<version>[^\s:]+)")

    @staticmethod
    def _is_urn(urn: str) -> bool:
        # URNs can be given as '<Publisher> <Offer> <Sku> <Version>' or '<Publisher>:<Offer>:<Sku>:<Version>'
        return AgentTestSuitesCombinator._URN.match(urn) is not None

    @staticmethod
    def _is_vhd(vhd: str) -> bool:
        # VHDs are given as URIs to storage; do some basic validation, not intending to be exhaustive.
        parsed = urllib.parse.urlparse(vhd)
        return parsed.scheme == 'https' and parsed.netloc != "" and parsed.path != ""
