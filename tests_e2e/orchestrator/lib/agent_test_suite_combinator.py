# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import logging

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

from dataclasses_json import dataclass_json

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'lisa' (import-error)
#     etc
from lisa import schema  # pylint: disable=E0401
from lisa.combinator import Combinator  # pylint: disable=E0401
from lisa.util import field_metadata  # pylint: disable=E0401

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader


@dataclass_json()
@dataclass
class AgentTestSuitesCombinatorSchema(schema.Combinator):
    test_suites: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )


class AgentTestSuitesCombinator(Combinator):
    """
    The "agent_test_suites" combinator returns a list of items containing five variables that specify the environments
    that the agent test suites must be executed on:

        * marketplace_image: e.g. "Canonical UbuntuServer 18.04-LTS latest",
        * location: e.g. "westus2",
        * vm_size: e.g. "Standard_D2pls_v5"
        * vhd: e.g "https://rhel.blob.core.windows.net/images/RHEL_8_Standard-8.3.202006170423.vhd?se=..."
        * test_suites_info: e.g. [AgentBvt, FastTrack]

    (marketplace_image, location, vm_size) and vhd are mutually exclusive and define the environment (i.e. the test VM)
    in which the test will be executed. test_suites_info defines the test suites that should be executed in that
    environment.
    """
    def __init__(self, runbook: AgentTestSuitesCombinatorSchema) -> None:
        super().__init__(runbook)
        self._environments = self.create_environment_list(self.runbook.test_suites)
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

    @staticmethod
    def create_environment_list(test_suites: str) -> List[Dict[str, Any]]:
        environment_list: List[Dict[str, Any]] = []
        shared_environments: Dict[str, Dict[str, Any]] = {}

        loader = AgentTestLoader(test_suites)

        for suite_info in loader.test_suites:
            images_info = loader.images[suite_info.images]
            for image in images_info:
                # If the suite specifies a location, use it. Else, if the image specifies a list of locations, use
                # any of them. Otherwise, use the default location.
                if suite_info.location != '':
                    location = suite_info.location
                elif len(image.locations) > 0:
                    location = image.locations[0]
                else:
                    location = AgentTestSuitesCombinator._DEFAULT_LOCATION

                # If the image specifies a list of VM sizes, use any of them. Otherwise, set the size to empty and let LISA choose it.
                vm_size = image.vm_sizes[0] if len(image.vm_sizes) > 0 else ""

                if suite_info.owns_vm:
                    environment_list.append({
                        "marketplace_image": image.urn,
                        "location": location,
                        "vm_size": vm_size,
                        "vhd": "",
                        "test_suites_info": [suite_info]
                    })
                else:
                    key: str = f"{image.urn}:{location}"
                    if key in shared_environments:
                        shared_environments[key]["test_suites_info"].append(suite_info)
                    else:
                        shared_environments[key] = {
                            "marketplace_image": image.urn,
                            "location": location,
                            "vm_size": vm_size,
                            "vhd": "",
                            "test_suites_info": [suite_info]
                        }

        environment_list.extend(shared_environments.values())

        log: logging.Logger = logging.getLogger("lisa")
        log.info("******** Environments *****")
        for e in environment_list:
            log.info(
                "{ marketplace_image: '%s', location: '%s', vm_size: '%s', vhd: '%s', test_suites_info: '%s' }",
                e['marketplace_image'], e['location'], e['vm_size'], e['vhd'], [s.name for s in e['test_suites_info']])
        log.info("***************************")

        return environment_list
