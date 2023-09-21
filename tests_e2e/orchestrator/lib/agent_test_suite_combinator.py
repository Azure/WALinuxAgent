# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import datetime
import json
import logging
import random
import re
import traceback
import urllib.parse
import uuid

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

# E0401: Unable to import 'dataclasses_json' (import-error)
from dataclasses_json import dataclass_json  # pylint: disable=E0401

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import notifier, schema  # pylint: disable=E0401
from lisa.combinator import Combinator  # pylint: disable=E0401
from lisa.messages import TestStatus, TestResultMessage
from lisa.util import get_public_key_data, field_metadata  # pylint: disable=E0401

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader, VmImageInfo, TestSuiteInfo
from tests_e2e.tests.lib.add_network_security_group import AddNetworkSecurityGroup
from tests_e2e.tests.lib.identifiers import RgIdentifier, VmssIdentifier
from tests_e2e.tests.lib.resource_group_client import ResourceGroupClient
from tests_e2e.tests.lib.virtual_machine_scale_set_client import VirtualMachineScaleSetClient


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
    subscription_id: str = field(
        default_factory=str, metadata=field_metadata(required=False)
    )
    user: str = field(
        default_factory=str, metadata=field_metadata(required=False)
    )
    identity_file: str = field(
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

        self._created_rgs = []
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
        log: logging.Logger = logging.getLogger("lisa")
        environments: List[Dict[str, Any]] = []
        shared_environments: Dict[str, Dict[str, Any]] = {}  # environments shared by multiple test suites

        loader = AgentTestLoader(self.runbook.test_suites, self.runbook.cloud)

        runbook_images = self._get_runbook_images(loader)

        skip_test_suites: List[str] = []
        for suite_info in loader.test_suites:
            if self.runbook.cloud in suite_info.skip_on_clouds:
                skip_test_suites.append(suite_info.name)
                continue
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
                        "c_location": c_location,
                        "c_vm_size": c_vm_size,
                        "c_vhd": c_vhd,
                        "c_test_suites": [suite_info],
                        "c_env_name": c_env_name,
                        "c_marketplace_image_information_location": self._MARKETPLACE_IMAGE_INFORMATION_LOCATIONS[self.runbook.cloud],
                        "c_shared_resource_group_location": self._SHARED_RESOURCE_GROUP_LOCATIONS[self.runbook.cloud],
                        "c_vm_tags": c_vm_tags,
                        "c_deploy": True
                    }
                # pylint: enable=W0640

                def create_environment_ext_sequencing(c_env_name: str) -> Dict[str, Any]:
                    log.info("Creating VMSS for ExtSequencing scenario")
                    curr_datetime = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                    rg_name = f"lisa-WALinuxAgent-extseq-{curr_datetime}-e{len(self._created_rgs)}"
                    vms = self._create_vmss_resources(c_env_name=c_env_name, rg_name=rg_name, location=c_location, urn=image.urn)
                    environment: Dict[str, Any] = {}
                    if len(vms) > 0:
                        environment = {
                            "c_env_name": env_name,
                            "c_vm_name": vms[0],
                            "c_location": c_location,
                            "c_test_suites": [suite_info],
                            "c_resource_group_name": rg_name,
                            "c_deploy": False
                        }
                    return environment

                if suite_info.owns_vm:
                    env_name = f"{image_name}-{suite_info.name}"
                    # The ExtSequencing scenario needs to be run on an instance of a scale set, which is not currently
                    # supported by Lisa. Creation of test resources for this scenario will be handled by the combinator.
                    if suite_info.name == "ExtSequencing":
                        env = create_environment_ext_sequencing(env_name)
                    else:
                        # create an environment for exclusive use by this suite
                        env = create_environment(env_name)

                    if env:
                        environments.append(env)
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

        if len(skip_test_suites) > 0:
            log.info("")
            log.info("Test suites skipped on %s:\n\n\t%s\n", self.runbook.cloud, '\n\t'.join(skip_test_suites))
        log.info("")
        log.info("******** Waagent: Test Environments *****")
        log.info("")
        log.info("Will execute tests on %d environments:\n\n\t%s\n", len(environments), '\n\t'.join([env['c_env_name'] for env in environments]))
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
                image_list = matching_images[0:int(count)]
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

    def _get_vmss_deployment_parameters(self, name: str, urn: str) -> Dict[str, Any]:
        image = urn.split(' ')
        ip_address = AddNetworkSecurityGroup()._my_ip_address
        return {
            "username": {
                "value": self.runbook.user
            },
            "sshPublicKey": {
                "value": get_public_key_data(self.runbook.identity_file)
            },
            "vmName": {
                "value": name
            },
            "scenarioPrefix": {
                "value": "ExtSequencing"
            },
            "publisher": {
                "value": image[0]
            },
            "offer": {
                "value": image[1]
            },
            "sku": {
                "value": image[2]
            },
            "version": {
                "value": image[3]
            },
            "ip_address": {
                "value": ip_address
            },
        }

    def _create_vmss_resources(self, c_env_name: str, rg_name: str, location: str, urn: str) -> List[str]:
        log: logging.Logger = logging.getLogger("lisa")
        rg = ResourceGroupClient(
            RgIdentifier(
                cloud=self.runbook.cloud,
                location=location,
                subscription=self.runbook.subscription_id,
                name=rg_name
            )
        )

        # Catch any failures creating resource and report as test failure
        try:
            # Create RG and keep name for cleanup
            rg.create()
            self._created_rgs.append(rg_name)

            # Create VMSS using ARM template
            template_file_path = Path(__file__).parent / "ext_seq_vmss_template.json"
            with open(template_file_path, "r") as f:
                template = json.load(f)
            parameters = self._get_vmss_deployment_parameters(name=rg_name.replace('-', '').lower(), urn=urn)
            rg.deploy_template(template, parameters)

            vmss = VirtualMachineScaleSetClient(
                VmssIdentifier(
                    cloud=self.runbook.cloud,
                    location=location,
                    subscription=self.runbook.subscription_id,
                    resource_group=rg_name,
                    name=parameters.get("vmName").get("value")
                )
            )
            vms = vmss.get_vm_instance_names()

            if len(vms) == 0:
                raise Exception("No VM instances were found in scale set")
            return vms
        except Exception:
            log.exception("Error creating test resources for ExtSequencing scenario")
            self._report_test_result(
                c_env_name,
                "ExtSeqVMSSResourceCreation",
                TestStatus.FAILED,
                datetime.datetime.now(),
                f"Error creating VMSS resources for {c_env_name}",
                add_exception_stack_trace=True)
            return []

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
