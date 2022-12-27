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
# BVT for extension operations (Install/Enable/Remove).
#
# The test executes an extension twice and then removes it. The actual extension is irrelevant, but the
# tests uses CustomScript for simplicity, since it's invocation is trivial and the entire workflow
# can be tested end-to-end by checking the message in the status produced by the extension.
#

import argparse
import uuid
import sys

from assertpy import assert_that
from azure.core.exceptions import ResourceNotFoundError

from tests_e2e.scenarios.lib.identifiers import VmIdentifier, VmExtensionIds
from tests_e2e.scenarios.lib.vm_extension import VmExtension


def main(vm: VmIdentifier):
    custom_script = VmExtension(vm, VmExtensionIds.CustomScript, resource_name="CustomScript")

    for _ in range(2):
        unique_id = uuid.uuid4()
        message = f"Hello {unique_id}!"
        custom_script.enable(settings={'commandToExecute': f"echo \'{message}\'"})

        instance_view = custom_script.get_instance_view()

        assert_that(instance_view.statuses).described_as(f"Expected 1 status, got: {instance_view.statuses}").is_length(1)
        status = instance_view.statuses[0]
        assert_that(status.code).described_as("InstanceView status code").is_equal_to('ProvisioningState/succeeded')
        assert_that(message in status.message).described_as(f"{message} should be in the InstanceView message ({status.message})").is_true()

    custom_script.delete()

    assert_that(custom_script.get_instance_view).\
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


