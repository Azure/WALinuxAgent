# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import logging
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

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader, VmImageInfo


@dataclass_json()
@dataclass
class AgentTestSuitesCombinatorSchema(schema.Combinator):
    test_suites: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    image: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    location: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )
    vm_size: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )


class AgentTestSuitesCombinator(Combinator):
    """
    The "agent_test_suites" combinator returns a list of items containing five variables that specify the environments
    that the agent test suites must be executed on:

        * c_marketplace_image: e.g. "Canonical UbuntuServer 18.04-LTS latest",
        * c_location: e.g. "westus2",
        * c_vm_size: e.g. "Standard_D2pls_v5"
        * c_vhd: e.g "https://rhel.blob.core.windows.net/images/RHEL_8_Standard-8.3.202006170423.vhd?se=..."
        * c_test_suites: e.g. [AgentBvt, FastTrack]

    (c_marketplace_image, c_location, c_vm_size) and vhd are mutually exclusive and define the environment (i.e. the test VM)
    in which the test will be executed. c_test_suites defines the test suites that should be executed in that
    environment.
    """
    def __init__(self, runbook: AgentTestSuitesCombinatorSchema) -> None:
        super().__init__(runbook)
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

    _DEFAULT_LOCATION = "westus2"

    def create_environment_list(self) -> List[Dict[str, Any]]:
        loader = AgentTestLoader(self.runbook.test_suites)

        #
        # If the runbook provides any of 'image', 'location', or 'vm_size', those values
        # override any configuration values on the test suite.
        #
        # Check 'images' first and add them to 'runbook_images', if any
        #
        if self.runbook.image == "":
            runbook_images = []
        else:
            runbook_images = loader.images.get(self.runbook.image)
            if runbook_images is None:
                if not self._is_urn(self.runbook.image) and not self._is_vhd(self.runbook.image):
                    raise Exception(f"The 'image' parameter must be an image or image set name, a urn, or a vhd: {self.runbook.image}")
                i = VmImageInfo()
                i.urn = self.runbook.image  # Note that this could be a URN or the URI for a VHD
                i.locations = []
                i.vm_sizes = []
                runbook_images = [i]

        #
        # Now walk through all the test_suites and create a list of the environments (test VMs) that need to be created.
        #
        environment_list: List[Dict[str, Any]] = []
        shared_environments: Dict[str, Dict[str, Any]] = {}

        for suite_info in loader.test_suites:
            images_info = runbook_images if len(runbook_images) > 0 else loader.images[suite_info.images]

            for image in images_info:
                # The URN can be a VHD if the runbook provided a VHD in the 'images' parameter
                if self._is_vhd(image.urn):
                    marketplace_image = ""
                    vhd = image.urn
                else:
                    marketplace_image = image.urn
                    vhd = ""

                # If the runbook specified a location, use it. Then try the suite location, if any. Otherwise, check if the image specifies
                # a list of locations and use any of them. If no location is specified so far, use the default.
                if self.runbook.location != "":
                    location = self.runbook.location
                elif suite_info.location != '':
                    location = suite_info.location
                elif len(image.locations) > 0:
                    location = image.locations[0]
                else:
                    location = AgentTestSuitesCombinator._DEFAULT_LOCATION

                # If the runbook specified a VM size, use it. Else if the image specifies a list of VM sizes, use any of them. Otherwise,
                # set the size to empty and let LISA choose it.
                if self.runbook.vm_size != '':
                    vm_size = self.runbook.vm_size
                elif len(image.vm_sizes) > 0:
                    vm_size = image.vm_sizes[0]
                else:
                    vm_size = ""

                if suite_info.owns_vm:
                    # create an environment for exclusive use by this suite
                    environment_list.append({
                        "c_marketplace_image": marketplace_image,
                        "c_location": location,
                        "c_vm_size": vm_size,
                        "c_vhd": vhd,
                        "c_test_suites": [suite_info]
                    })
                else:
                    # add this suite to the shared environments
                    key: str = f"{image.urn}:{location}"
                    if key in shared_environments:
                        shared_environments[key]["c_test_suites"].append(suite_info)
                    else:
                        shared_environments[key] = {
                            "c_marketplace_image": marketplace_image,
                            "c_location": location,
                            "c_vm_size": vm_size,
                            "c_vhd": vhd,
                            "c_test_suites": [suite_info]
                        }

        environment_list.extend(shared_environments.values())

        log: logging.Logger = logging.getLogger("lisa")
        log.info("******** Environments *****")
        for e in environment_list:
            log.info(
                "{ c_marketplace_image: '%s', c_location: '%s', c_vm_size: '%s', c_vhd: '%s', c_test_suites: '%s' }",
                e['c_marketplace_image'], e['c_location'], e['c_vm_size'], e['c_vhd'], [s.name for s in e['c_test_suites']])
        log.info("***************************")

        return environment_list

    @staticmethod
    def _is_urn(urn: str) -> bool:
        # URNs can be given as '<Publisher> <Offer> <Sku> <Version>' or '<Publisher>:<Offer>:<Sku>:<Version>'
        return re.match(r"(\S+\s\S+\s\S+\s\S+)|([^:]+:[^:]+:[^:]+:[^:]+)", urn) is not None

    @staticmethod
    def _is_vhd(vhd: str) -> bool:
        # VHDs are given as URIs to storage; do some basic validation, not intending to be exhaustive.
        parsed = urllib.parse.urlparse(vhd)
        return parsed.scheme == 'https' and parsed.netloc != "" and parsed.path != ""
