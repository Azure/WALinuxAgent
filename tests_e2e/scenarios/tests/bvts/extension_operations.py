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

#
# BVT for extension operations (Install/Enable/Update/Uninstall).
#
# The test executes an older version of an extension, then updates it to a newer version, and lastly
# it removes it. The actual extension is irrelevant, but the test uses CustomScript for simplicity,
# since it's invocation is trivial and the entire extension workflow  can be tested end-to-end by
# checking the message in the status produced by the extension.
#

import argparse
import uuid
import sys

from assertpy import assert_that

from azure.core.exceptions import ResourceNotFoundError

from tests_e2e.scenarios.lib.identifiers import VmIdentifier, VmExtensionIds
from tests_e2e.scenarios.lib.logging import log
from tests_e2e.scenarios.lib.vm_extension import VmExtension


def main(vm: VmIdentifier):
    def validate(extension: VmExtension, expected_version: str, expected_message: str):
        instance_view = extension.get_instance_view()

        # Compare only the major and minor versions (i.e. the first 2 items in the result of split()
        installed_version = instance_view.type_handler_version
        assert_that(expected_version.split(".")[0:2]).described_as("Unexpected extension version").is_equal_to(installed_version.split(".")[0:2])

        assert_that(instance_view.statuses).described_as(f"Expected 1 status, got: {instance_view.statuses}").is_length(1)
        status = instance_view.statuses[0]
        assert_that(status.code).described_as("InstanceView status code").is_equal_to('ProvisioningState/succeeded')

        assert_that(expected_message in status.message).described_as(f"{message} should be in the InstanceView message ({status.message})").is_true()

    custom_script_2_0 = VmExtension(vm, VmExtensionIds.CustomScript_2_0, resource_name="CustomScript")
    custom_script_2_1 = VmExtension(vm, VmExtensionIds.CustomScript_2_1, resource_name="CustomScript")

    log.info("Installing %s", custom_script_2_0)
    message = f"Hello {uuid.uuid4()}!"
    custom_script_2_0.enable(settings={'commandToExecute': f"echo \'{message}\'"}, auto_upgrade_minor_version=False)
    validate(custom_script_2_0, "2.0", message)

    log.info("Updating %s to %s", custom_script_2_0, custom_script_2_1)
    message = f"Hello {uuid.uuid4()}!"
    custom_script_2_1.enable(settings={'commandToExecute': f"echo \'{message}\'"})
    validate(custom_script_2_1, "2.1", message)

    custom_script_2_1.delete()

    assert_that(custom_script_2_1.get_instance_view).\
        described_as("Fetching the instance view should fail after removing the extension").\
        raises(ResourceNotFoundError)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--location', required=True)
        parser.add_argument('--subscription', required=True)
        parser.add_argument('--group', required=True)
        parser.add_argument('--vm', required=True)

        args = parser.parse_args()

        vm_id = VmIdentifier(location=args.location, subscription=args.subscription, resource_group=args.group, name=args.vm)

        main(vm_id)

    except Exception as exception:
        print(str(exception))
        sys.exit(1)

    sys.exit(0)


