# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import datetime
import logging
import random
import re
import traceback
import urllib.parse
import uuid

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

# E0401: Unable to import 'dataclasses_json' (import-error)
from dataclasses_json import dataclass_json  # pylint: disable=E0401

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import notifier, schema  # pylint: disable=E0401
from lisa.combinator import Combinator  # pylint: disable=E0401
from lisa.messages import TestStatus, TestResultMessage  # pylint: disable=E0401
from lisa.util import field_metadata  # pylint: disable=E0401

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader, VmImageInfo, TestSuiteInfo
from tests_e2e.tests.lib.logging import set_thread_name
from tests_e2e.tests.lib.virtual_machine_client import VirtualMachineClient
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VirtualMachineScaleSetClient


@dataclass_json()
@dataclass
class AgentTestSuitesCombinatorSchema(schema.Combinator):
    """
    Defines the parameters passed to the combinator from the runbook.

    The runbook is a static document and always passes all these parameters to the combinator, so they are all
    marked as required. Optional parameters can pass an empty value to indicate that they are not specified.
    """
    allow_ssh: str = field(default_factory=str, metadata=field_metadata(required=True))
    cloud: str = field(default_factory=str, metadata=field_metadata(required=True))
    identity_file: str = field(default_factory=str, metadata=field_metadata(required=True))
    image: str = field(default_factory=str, metadata=field_metadata(required=True))
    keep_environment: str = field(default_factory=str, metadata=field_metadata(required=True))
    location: str = field(default_factory=str, metadata=field_metadata(required=True))
    resource_group_name: str = field(default_factory=str, metadata=field_metadata(required=True))
    subscription_id: str = field(default_factory=str, metadata=field_metadata(required=True))
    test_suites: str = field(default_factory=str, metadata=field_metadata(required=True))
    default_test_suites: List[str] = field(default_factory=list, metadata=field_metadata(required=True))
    user: str = field(default_factory=str, metadata=field_metadata(required=True))
    vm_name: str = field(default_factory=str, metadata=field_metadata(required=True))
    vm_size: str = field(default_factory=str, metadata=field_metadata(required=True))
    vmss_name: str = field(default_factory=str, metadata=field_metadata(required=True))


class AgentTestSuitesCombinator(Combinator):
    """
    The "agent_test_suites" combinator returns a list of variables that specify the test environments (i.e. test VMs) that the
    test suites must be executed on. These variables are prefixed with "c_" to distinguish them from the command line arguments
    of the runbook. See the runbook definition for details on each of those variables.

    The combinator can generate environments for VMs created and managed by LISA, Scale Sets created and managed by the AgentTestSuite,
    or existing VMs or Scale Sets.
    """
    def __init__(self, runbook: AgentTestSuitesCombinatorSchema) -> None:
        super().__init__(runbook)
        if self.runbook.cloud not in self._DEFAULT_LOCATIONS:
            raise Exception(f"Invalid cloud: {self.runbook.cloud}")

        if self.runbook.vm_name != '' and self.runbook.vmss_name != '':
            raise Exception("Invalid runbook parameters: 'vm_name' and 'vmss_name' are mutually exclusive.")

        if self.runbook.vm_name != '':
            if self.runbook.image != '' or self.runbook.vm_size != '':
                raise Exception("Invalid runbook parameters: The 'vm_name' parameter indicates an existing VM, 'image' and 'vm_size' should not be specified.")
            if self.runbook.resource_group_name == '':
                raise Exception("Invalid runbook parameters: The 'vm_name' parameter indicates an existing VM, a 'resource_group_name' must be specified.")

        if self.runbook.vmss_name != '':
            if self.runbook.image != '' or self.runbook.vm_size != '':
                raise Exception("Invalid runbook parameters: The 'vmss_name' parameter indicates an existing VMSS, 'image' and 'vm_size' should not be specified.")
            if self.runbook.resource_group_name == '':
                raise Exception("Invalid runbook parameters: The 'vmss_name' parameter indicates an existing VMSS, a 'resource_group_name' must be specified.")

        if self.runbook.test_suites != "":
            test_suites = [t.strip() for t in self.runbook.test_suites.split(',')]
        else:
            test_suites = self.runbook.default_test_suites

        self._log: logging.Logger = logging.getLogger("lisa")

        with set_thread_name("AgentTestSuitesCombinator"):
            if self.runbook.vm_name != '':
                self._environments = [self.create_existing_vm_environment(test_suites)]
            elif self.runbook.vmss_name != '':
                self._environments = [self.create_existing_vmss_environment(test_suites)]
            else:
                self._environments = self.create_environment_list(test_suites)
            self._index = 0

    @classmethod
    def type_name(cls) -> str:
        return "agent_test_suite_combinator"

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

    def create_environment_list(self, test_suites: List[str]) -> List[Dict[str, Any]]:
        """
        Examines the test_suites specified in the runbook and returns a list of the environments (i.e. test VMs or scale sets) that need to be
        created in order to execute these suites.

        Note that if the runbook provides an 'image', 'location', or 'vm_size', those values override any values provided in the
        configuration of the test suites.
        """
        environments: List[Dict[str, Any]] = []
        shared_environments: Dict[str, Dict[str, Any]] = {}  # environments shared by multiple test suites

        loader = AgentTestLoader(test_suites, self.runbook.cloud)

        runbook_images = self._get_runbook_images(loader)

        skip_test_suites: List[str] = []
        skip_test_suites_images: List[str] = []
        for test_suite_info in loader.test_suites:
            if self.runbook.cloud in test_suite_info.skip_on_clouds:
                skip_test_suites.append(test_suite_info.name)
                continue
            if len(runbook_images) > 0:
                images_info: List[VmImageInfo] = runbook_images
            else:
                images_info: List[VmImageInfo] = self._get_test_suite_images(test_suite_info, loader)

            skip_images_info: List[VmImageInfo] = self._get_test_suite_skip_images(test_suite_info, loader)
            if len(skip_images_info) > 0:
                skip_test_suite_image = f"{test_suite_info.name}: {','.join([i.urn for i in skip_images_info])}"
                skip_test_suites_images.append(skip_test_suite_image)

            for image in images_info:
                if image in skip_images_info:
                    continue
                # 'image.urn' can actually be the URL to a VHD or an image from a gallery if the runbook provided it in the 'image' parameter
                if self._is_vhd(image.urn):
                    marketplace_image = ""
                    vhd = image.urn
                    image_name = urllib.parse.urlparse(vhd).path.split('/')[-1]  # take the last fragment of the URL's path (e.g. "RHEL_8_Standard-8.3.202006170423.vhd")
                    shared_gallery = ""
                elif self._is_image_from_gallery(image.urn):
                    marketplace_image = ""
                    vhd = ""
                    image_name = self._get_name_of_image_from_gallery(image.urn)
                    shared_gallery = image.urn
                else:
                    marketplace_image = image.urn
                    vhd = ""
                    image_name = self._get_image_name(image.urn)
                    shared_gallery = ""

                if test_suite_info.executes_on_scale_set and (vhd != "" or shared_gallery != ""):
                    raise Exception("VHDS and images from galleries are currently not supported on scale sets.")

                location: str = self._get_location(test_suite_info, image)
                if location is None:
                    continue

                vm_size = self._get_vm_size(image)

                if test_suite_info.owns_vm or not test_suite_info.install_test_agent:
                    #
                    # Create an environment for exclusive use by this suite
                    #
                    # TODO: Allow test suites that set 'install_test_agent' to False to share environments (we need to ensure that
                    #       all the suites in the shared environment have the same value for 'install_test_agent')
                    #
                    if test_suite_info.executes_on_scale_set:
                        env = self.create_vmss_environment(
                            env_name=f"{image_name}-vmss-{test_suite_info.name}",
                            marketplace_image=marketplace_image,
                            location=location,
                            vm_size=vm_size,
                            test_suite_info=test_suite_info)
                    else:
                        env = self.create_vm_environment(
                            env_name=f"{image_name}-{test_suite_info.name}",
                            marketplace_image=marketplace_image,
                            vhd=vhd,
                            shared_gallery=shared_gallery,
                            location=location,
                            vm_size=vm_size,
                            test_suite_info=test_suite_info)
                    environments.append(env)
                else:
                    # add this suite to the shared environments
                    env_name: str = f"{image_name}-vmss-{location}" if test_suite_info.executes_on_scale_set else f"{image_name}-{location}"
                    env = shared_environments.get(env_name)
                    if env is not None:
                        env["c_test_suites"].append(test_suite_info)
                    else:
                        if test_suite_info.executes_on_scale_set:
                            env = self.create_vmss_environment(
                                env_name=env_name,
                                marketplace_image=marketplace_image,
                                location=location,
                                vm_size=vm_size,
                                test_suite_info=test_suite_info)
                        else:
                            env = self.create_vm_environment(
                                env_name=env_name,
                                marketplace_image=marketplace_image,
                                vhd=vhd,
                                shared_gallery=shared_gallery,
                                location=location,
                                vm_size=vm_size,
                                test_suite_info=test_suite_info)
                        shared_environments[env_name] = env

                if test_suite_info.template != '':
                    vm_tags = env["vm_tags"]
                    if "templates" not in vm_tags:
                        vm_tags["templates"] = test_suite_info.template
                    else:
                        vm_tags["templates"] += "," + test_suite_info.template

        environments.extend(shared_environments.values())

        if len(environments) == 0:
            raise Exception("No VM images were found to execute the test suites.")

        # Log a summary of each environment and the suites that will be executed on it
        format_suites = lambda suites: ", ".join([s.name for s in suites])
        summary = [f"{e['c_env_name']}: [{format_suites(e['c_test_suites'])}]" for e in environments]
        summary.sort()
        self._log.info("Executing tests on %d environments\n\n%s\n", len(environments), '\n'.join([f"\t{s}" for s in summary]))

        if len(skip_test_suites) > 0:
            self._log.info("Skipping test suites %s", skip_test_suites)

        if len(skip_test_suites_images) > 0:
            self._log.info("Skipping test suits run on images \n %s", '\n'.join([f"\t{skip}" for skip in skip_test_suites_images]))

        return environments

    def create_existing_vm_environment(self, test_suites: List[str]) -> Dict[str, Any]:
        loader = AgentTestLoader(test_suites, self.runbook.cloud)

        vm: VirtualMachineClient = VirtualMachineClient(
            cloud=self.runbook.cloud,
            location=self.runbook.location,
            subscription=self.runbook.subscription_id,
            resource_group=self.runbook.resource_group_name,
            name=self.runbook.vm_name)

        ip_address = vm.get_ip_address()

        return {
            "c_env_name": self.runbook.vm_name,
            "c_platform": [
                {
                    "type": "ready",
                    "capture_vm_information": False
                }
            ],
            "c_environment": {
                "environments": [
                    {
                        "nodes": [
                            {
                                "type": "remote",
                                "name": self.runbook.vm_name,
                                "public_address": ip_address,
                                "public_port": 22,
                                "username": self.runbook.user,
                                "private_key_file": self.runbook.identity_file
                            }
                        ],
                    }
                ]
            },
            "c_location": self.runbook.location,
            "c_test_suites": loader.test_suites,
        }

    def create_existing_vmss_environment(self, test_suites: List[str]) -> Dict[str, Any]:
        loader = AgentTestLoader(test_suites, self.runbook.cloud)

        vmss = VirtualMachineScaleSetClient(
            cloud=self.runbook.cloud,
            location=self.runbook.location,
            subscription=self.runbook.subscription_id,
            resource_group=self.runbook.resource_group_name,
            name=self.runbook.vmss_name)

        ip_addresses = vmss.get_instances_ip_address()

        return {
            "c_env_name": self.runbook.vmss_name,
            "c_environment": {
                "environments": [
                    {
                        "nodes": [
                            {
                                "type": "remote",
                                "name": i.instance_name,
                                "public_address": i.ip_address,
                                "public_port": 22,
                                "username": self.runbook.user,
                                "private_key_file": self.runbook.identity_file
                            } for i in ip_addresses
                        ],
                    }
                ]
            },
            "c_platform": [
                {
                    "type": "ready",
                    "capture_vm_information": False
                }
            ],
            "c_location": self.runbook.location,
            "c_test_suites": loader.test_suites,
        }

    def create_vm_environment(self, env_name: str, marketplace_image: str, vhd: str, shared_gallery: str, location: str, vm_size: str, test_suite_info: TestSuiteInfo) -> Dict[str, Any]:
        #
        # Custom ARM templates (to create the test VMs) require special handling. These templates are processed by the azure_update_arm_template
        # hook, which does not have access to the runbook variables. Instead, we use a dummy VM tag named "templates" and pass the
        # names of the custom templates in its value. The hook can then retrieve the value from the Platform object (see wiki for more details).
        # We also use a dummy item, "vm_tags" in the environment dictionary in order to concatenate templates from multiple test suites when they
        # share the same test environment. Similarly, we use a dummy VM tag named "allow_ssh" to pass the value of the "allow_ssh" runbook parameter.
        #
        vm_tags = {}
        if self.runbook.allow_ssh != '':
            vm_tags["allow_ssh"] = self.runbook.allow_ssh
        environment = {
            "c_platform": [
                {
                    "type": "azure",
                    "admin_username": self.runbook.user,
                    "admin_private_key_file": self.runbook.identity_file,
                    "keep_environment": self.runbook.keep_environment,
                    "capture_vm_information": False,
                    "azure": {
                        "deploy": True,
                        "cloud": self.runbook.cloud,
                        "marketplace_image_information_location": self._MARKETPLACE_IMAGE_INFORMATION_LOCATIONS[self.runbook.cloud],
                        "shared_resource_group_location": self._SHARED_RESOURCE_GROUP_LOCATIONS[self.runbook.cloud],
                        "subscription_id": self.runbook.subscription_id,
                        "wait_delete": False,
                        "vm_tags": vm_tags
                    },
                    "requirement": {
                        "core_count": {
                            "min": 2
                        },
                        "azure": {
                            "marketplace": marketplace_image,
                            "vhd": vhd,
                            "shared_gallery": shared_gallery,
                            "location": location,
                            "vm_size": vm_size
                        }
                    }
                }
            ],

            "c_environment": None,

            "c_env_name": env_name,
            "c_test_suites": [test_suite_info],
            "c_location": location,
            "c_image": marketplace_image,
            "c_is_vhd": vhd != "",
            "vm_tags": vm_tags
        }

        if shared_gallery != '':
            # Currently all the images in our shared gallery require secure boot
            environment['c_platform'][0]['requirement']["features"] = {
                "items": [
                    {
                        "type": "Security_Profile",
                        "security_profile": "secureboot"
                    }
                ]
            }
        return environment

    def create_vmss_environment(self, env_name: str, marketplace_image: str, location: str, vm_size: str, test_suite_info: TestSuiteInfo) -> Dict[str, Any]:
        return {
            "c_platform": [
                {
                    "type": "ready",
                    "capture_vm_information": False
                }
            ],

            "c_environment": {
                "environments": [
                    {
                        "nodes": [
                            {"type": "local"}
                        ],
                    }
                ]
            },

            "c_env_name": env_name,
            "c_test_suites": [test_suite_info],
            "c_location": location,
            "c_image": marketplace_image,
            "c_is_vhd": False,
            "c_vm_size": vm_size,
            "vm_tags": {}
        }

    def _get_runbook_images(self, loader: AgentTestLoader) -> List[VmImageInfo]:
        """
        Returns the images specified in the runbook, or an empty list if none are specified.
        """
        if self.runbook.image == "":
            return []

        images = loader.images.get(self.runbook.image)
        if images is not None:
            return images

        # If it is not image or image set, it must be a URN, VHD, or an image from a gallery
        if not self._is_urn(self.runbook.image) and not self._is_vhd(self.runbook.image) and not self._is_image_from_gallery(self.runbook.image):
            raise Exception(f"The 'image' parameter must be an image, image set name, urn, vhd, or an image from a shared gallery: {self.runbook.image}")

        i = VmImageInfo()
        i.urn = self.runbook.image  # Note that this could be a URN or the URI for a VHD, or an image from a shared gallery
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
                image_list = matching_images[0:int(count)]
            for i in image_list:
                unique[i.urn] = i
        return [v for k, v in unique.items()]

    @staticmethod
    def _get_test_suite_skip_images(suite: TestSuiteInfo, loader: AgentTestLoader) -> List[VmImageInfo]:
        """
        Returns images that need to be skipped by the suite.

        A test suite may reference multiple image sets and sets can intersect; this method eliminates any duplicates.
        """
        skip_unique: Dict[str, VmImageInfo] = {}
        for image in suite.skip_on_images:
            image_list = loader.images[image]
            for i in image_list:
                skip_unique[i.urn] = i
        return [v for k, v in skip_unique.items()]

    def _get_location(self, suite_info: TestSuiteInfo, image: VmImageInfo) -> str:
        """
        Returns the location on which the test VM for the given test suite and image should be created.

        If the image is not available on any location, returns None, to indicate that the test suite should be skipped.
        """
        # If the runbook specified a location, use it.
        if self.runbook.location != "":
            return self.runbook.location

        #  Then try the suite location, if any.
        for location in suite_info.locations:
            if location.startswith(self.runbook.cloud + ":"):
                return location.split(":")[1]

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

    # Images from a gallery are given as  "<image_gallery>/<image_definition>/<image_version>".
    _IMAGE_FROM_GALLERY = re.compile(r"(?P<gallery>[^/]+)/(?P<image>[^/]+)/(?P<version>[^/]+)")

    @staticmethod
    def _is_image_from_gallery(image: str) -> bool:
        return AgentTestSuitesCombinator._IMAGE_FROM_GALLERY.match(image) is not None

    @staticmethod
    def _get_name_of_image_from_gallery(image: str) -> bool:
        match = AgentTestSuitesCombinator._IMAGE_FROM_GALLERY.match(image)
        if match is None:
            raise Exception(f"Invalid image from gallery: {image}")
        return match.group('image')

    @staticmethod
    def _report_test_result(
            suite_name: str,
            test_name: str,
            status: TestStatus,
            start_time: datetime.datetime,
            message: str = "",
            add_exception_stack_trace: bool = False
    ) -> None:
        """
        Reports a test result to the junit notifier
        """
        # The junit notifier requires an initial RUNNING message in order to register the test in its internal cache.
        msg: TestResultMessage = TestResultMessage()
        msg.type = "AgentTestResultMessage"
        msg.id_ = str(uuid.uuid4())
        msg.status = TestStatus.RUNNING
        msg.suite_full_name = suite_name
        msg.suite_name = msg.suite_full_name
        msg.full_name = test_name
        msg.name = msg.full_name
        msg.elapsed = 0

        notifier.notify(msg)

        # Now send the actual result. The notifier pipeline makes a deep copy of the message so it is OK to re-use the
        # same object and just update a few fields. If using a different object, be sure that the "id_" is the same.
        msg.status = status
        msg.message = message
        if add_exception_stack_trace:
            msg.stacktrace = traceback.format_exc()
        msg.elapsed = (datetime.datetime.now() - start_time).total_seconds()

        notifier.notify(msg)
