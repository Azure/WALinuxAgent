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

import importlib
import logging
from pathlib import Path
from typing import Any, Callable

# Disable those warnings, since 'lisa' is an external, non-standard, dependency
# E0401: Unable to import 'lisa.*' (import-error)
# pylint: disable=E0401
from lisa.environment import Environment
from lisa.util import hookimpl, plugin_manager
from lisa.sut_orchestrator.azure.platform_ import AzurePlatformSchema
# pylint: enable=E0401

import tests_e2e


class UpdateArmTemplateHook:
    """
    This hook allows to customize the ARM template used to create the test VMs (see wiki for details).
    """
    @hookimpl
    def azure_update_arm_template(self, template: Any, environment: Environment) -> None:
        azure_runbook: AzurePlatformSchema = environment.platform.runbook.get_extended_runbook(AzurePlatformSchema)
        vm_tags = azure_runbook.vm_tags
        templates = vm_tags.get("templates")
        if templates is not None:
            log: logging.Logger = logging.getLogger("lisa")
            log.info("******** Waagent: Applying custom templates '%s' to environment '%s'", templates, environment.name)

            for t in templates.split(","):
                update_arm_template = self._get_update_arm_template(t)
                update_arm_template(template)

    _SOURCE_CODE_ROOT: Path = Path(tests_e2e.__path__[0])

    @staticmethod
    def _get_update_arm_template(template_path: str) -> Callable:
        source_file: Path = UpdateArmTemplateHook._SOURCE_CODE_ROOT/"tests"/template_path

        spec = importlib.util.spec_from_file_location(f"tests_e2e.tests.templates.{source_file.name}", str(source_file))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        matches = [v for v in module.__dict__.values() if callable(v) and v.__name__ == "update_arm_template"]
        if len(matches) != 1:
            raise Exception(f"Could not find update_arm_template in {source_file}")
        return matches[0]


plugin_manager.register(UpdateArmTemplateHook())
