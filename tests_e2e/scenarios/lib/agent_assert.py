#!/usr/bin/env python3

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
# This module provides convenience functions to evaluate assertions common to multiple tests
#


from assertpy import assert_that, soft_assertions
from typing import Any, Callable

from tests_e2e.scenarios.lib.vm_extension import VmExtension


def assert_instance_view(
    extension: VmExtension,
    expected_status_code: str = "ProvisioningState/succeeded",
    expected_version: str = None,
    expected_message: str = None,
    assert_function: Callable[[Any], None] = None
) -> None:
    """
    Asserts that the extension's instance view matches the given expected values. If 'expected_version' and/or 'expected_message'
    are omitted, they are not validated.

    If 'assert_function' is provided, it is invoked passing as parameter the instance view. This function can be used to perform
    additional validations.
    """
    instance_view = extension.get_instance_view()

    with soft_assertions():
        if expected_version is not None:
            # Compare only the major and minor versions (i.e. the first 2 items in the result of split()
            installed_version = instance_view.type_handler_version
            assert_that(expected_version.split(".")[0:2]).described_as("Unexpected extension version").is_equal_to(installed_version.split(".")[0:2])

        assert_that(instance_view.statuses).described_as(f"Expected 1 status, got: {instance_view.statuses}").is_length(1)
        status = instance_view.statuses[0]

        if expected_message is not None:
            assert_that(expected_message in status.message).described_as(f"{expected_message} should be in the InstanceView message ({status.message})").is_true()

        assert_that(status.code).described_as("InstanceView status code").is_equal_to(expected_status_code)

        if assert_function is not None:
            assert_function(instance_view)
