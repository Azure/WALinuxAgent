# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

from dataclasses_json import dataclass_json

from lisa import schema
from lisa.combinator import Combinator
from lisa.util import field_metadata

from tests_e2e.orchestrator.lib.agent_test_loader import AgentTestLoader


@dataclass_json()
@dataclass
class AgentTestSuitesCombinatorSchema(schema.Combinator):
    test_suites: str = field(
        default_factory=str, metadata=field_metadata(required=True)
    )


class AgentTestSuitesCombinator(Combinator):
    """
    The "agent_test_suites" combinator returns a list of items containing four variables that specify the environments
    that the agent test suites must be executed on:

        * marketplace_image: e.g. "Canonical UbuntuServer 18.04-LTS latest",
        * location: e.g. "westus2",
        * vm_size: e.g. "Standard_D2pls_v5"
        * vhd: e.g "https://rhel.blob.core.windows.net/images/RHEL_8_Standard-8.3.202006170423.vhd?se=..."

    NOTE: "marketplace_image" and "vhd" are mutually exclusive.

    """
    def __init__(self, runbook: AgentTestSuitesCombinatorSchema) -> None:
        super().__init__(runbook)
        self._items = self.create_test_environment_list(self.runbook.test_suites)
        self._index = 0

    @classmethod
    def type_name(cls) -> str:
        return "agent_test_suites"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return AgentTestSuitesCombinatorSchema

    def _next(self) -> Optional[Dict[str, Any]]:
        result: Optional[Dict[str, Any]] = None
        if self._index < len(self._items):
            result = self._items[self._index]
            self._index += 1
        return result

    _DEFAULT_LOCATION = "westus2"

    @staticmethod
    def create_environment_list(test_suites: str) -> List[Dict[str, Any]]:
        environment_list: List[Dict[str, Any]] = []

        loader = AgentTestLoader(test_suites, load_tests=False)

        for suite in loader.test_suites:
            for image in loader.images[suite.images]:
                # if the suite specifies a location, use it. Otherwise, if the image specifies a list of locations, use
                # any of them. Otherwise, use the default location.
                if suite.location != '':
                    location = suite.location
                elif len(image.locations) > 0:
                    location = image.locations[0]
                else:
                    location = AgentTestSuitesCombinator._DEFAULT_LOCATION

                # If the image specifies a list of VM sizes, use any of them. Otherwise, set the size to empty and let LISA choose it.
                vm_size = image.vm_sizes[0] if len(image.vm_sizes) > 0 else ""

                environment_list.append({
                    "marketplace_image": image.urn,
                    "location": location,
                    "vm_size": vm_size,
                    "vhd": "",
                })

        return environment_list
