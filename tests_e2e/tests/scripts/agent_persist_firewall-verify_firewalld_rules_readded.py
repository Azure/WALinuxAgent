#!/usr/bin/env pypy3
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
# This script deleting the firewalld rules and ensure deleted rules added back to the firewalld rule set after agent start
#

from azurelinuxagent.common.osutil import get_osutil
from tests_e2e.tests.lib.firewall_helpers import firewalld_service_running, print_current_firewalld_rules, \
    get_non_root_accept_tcp_firewalld_rule, get_all_firewalld_rule_commands, FirewalldRules, execute_cmd, \
    check_if_firewalld_rule_is_available, verify_all_firewalld_rules_exist, get_root_accept_firewalld_rule, \
    get_non_root_drop_firewalld_rule
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry


def delete_firewalld_rules(commands=None):
    """
    This function is used to delete the provided rule or all(if not specified) from the firewalld rules
    """
    if commands is None:
        commands = []
    if not commands:
        root_accept, non_root_accept, non_root_drop = get_all_firewalld_rule_commands(FirewalldRules.REMOVE_PASSTHROUGH)
        commands.extend([root_accept, non_root_accept, non_root_drop])

    log.info("Deleting firewalld rules \n %s", commands)

    try:
        cmd = None
        for command in commands:
            cmd = command
            # W0640: Cell variable cmd defined in loop (cell-var-from-loop)
            retry(lambda: execute_cmd(cmd=cmd), attempts=3)  # pylint: disable=W0640
    except Exception as e:
        raise Exception("Error -- Failed to Delete the firewalld rule set {0}".format(e))

    log.info("Success --Deletion of firewalld rule")


def verify_rules_deleted_successfully(commands=None):
    """
    This function is used to verify if provided rule or all(if not specified) rules are deleted successfully.
    """
    log.info("Verifying requested rules deleted successfully")

    if commands is None:
        commands = []

    if not commands:
        root_accept, non_root_accept, non_root_drop = get_all_firewalld_rule_commands(FirewalldRules.QUERY_PASSTHROUGH)
        commands.extend([root_accept, non_root_accept, non_root_drop])

    # "--QUERY-PASSTHROUGH" return error code 1 when not available which is expected after deletion
    for command in commands:
        if not check_if_firewalld_rule_is_available(command):
            pass
        else:
            raise Exception("Deletion of firewalld rules not successful\n.Current firewalld rules:\n" + print_current_firewalld_rules())

    log.info("firewalld rules deleted successfully \n %s", commands)


def verify_non_root_accept_rule():
    """
    This function verifies the non root accept rule and make sure it is re added by agent after deletion
    """
    log.info("verifying non root accept rule")
    agent_name = get_osutil().get_service_name()
    # stop the agent, so that it won't re-add rules while checking
    log.info("stop the agent, so that it won't re-add rules while checking")
    cmd = ["systemctl", "stop", agent_name]
    execute_cmd(cmd)

    # deleting tcp rule
    accept_tcp_rule_with_delete = get_non_root_accept_tcp_firewalld_rule(FirewalldRules.REMOVE_PASSTHROUGH)
    delete_firewalld_rules([accept_tcp_rule_with_delete])

    # verifying deletion successful
    accept_tcp_rule_with_check = get_non_root_accept_tcp_firewalld_rule(FirewalldRules.QUERY_PASSTHROUGH)
    verify_rules_deleted_successfully([accept_tcp_rule_with_check])

    # restart the agent to re-add the deleted rules
    log.info("restart the agent to re-add the deleted rules")
    cmd = ["systemctl", "restart", agent_name]
    execute_cmd(cmd=cmd)

    verify_all_firewalld_rules_exist()


def verify_root_accept_rule():
    """
    This function verifies the root accept rule and make sure it is re added by agent after deletion
    """
    log.info("Verifying root accept rule")
    agent_name = get_osutil().get_service_name()
    # stop the agent, so that it won't re-add rules while checking
    log.info("stop the agent, so that it won't re-add rules while checking")
    cmd = ["systemctl", "stop", agent_name]
    execute_cmd(cmd)

    # deleting root accept rule
    root_accept_rule_with_delete = get_root_accept_firewalld_rule(FirewalldRules.REMOVE_PASSTHROUGH)
    delete_firewalld_rules([root_accept_rule_with_delete])

    # verifying deletion successful
    root_accept_rule_with_check = get_root_accept_firewalld_rule(FirewalldRules.QUERY_PASSTHROUGH)
    verify_rules_deleted_successfully([root_accept_rule_with_check])

    # restart the agent to re-add the deleted rules
    log.info("restart the agent to re-add the deleted rules")
    cmd = ["systemctl", "restart", agent_name]
    execute_cmd(cmd=cmd)

    verify_all_firewalld_rules_exist()


def verify_non_root_drop_rule():
    """
    This function verifies drop rule and make sure it is re added by agent after deletion
    """
    log.info("Verifying non root drop rule")
    agent_name = get_osutil().get_service_name()
    # stop the agent, so that it won't re-add rules while checking
    log.info("stop the agent, so that it won't re-add rules while checking")
    cmd = ["systemctl", "stop", agent_name]
    execute_cmd(cmd)

    # deleting non-root drop rule
    non_root_drop_with_delete = get_non_root_drop_firewalld_rule(FirewalldRules.REMOVE_PASSTHROUGH)
    delete_firewalld_rules([non_root_drop_with_delete])

    # verifying deletion successful
    non_root_drop_with_check = get_non_root_drop_firewalld_rule(FirewalldRules.QUERY_PASSTHROUGH)
    verify_rules_deleted_successfully([non_root_drop_with_check])

    # restart the agent to re-add the deleted rules
    log.info("restart the agent to re-add the deleted rules")
    cmd = ["systemctl", "restart", agent_name]
    execute_cmd(cmd=cmd)

    verify_all_firewalld_rules_exist()


def main():

    if firewalld_service_running():
        log.info("Displaying current firewalld rules")
        print_current_firewalld_rules()
        verify_non_root_accept_rule()
        verify_root_accept_rule()
        verify_non_root_drop_rule()
    else:
        log.info("firewalld.service is not running and skipping test")


if __name__ == "__main__":
    main()
