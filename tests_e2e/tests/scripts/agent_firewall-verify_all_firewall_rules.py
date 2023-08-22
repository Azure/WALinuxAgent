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
# This script checks all agent firewall rules added properly and working as expected
#
import argparse
import os
import pwd
import socket
from typing import List, Tuple

from assertpy import fail

from azurelinuxagent.common.utils import shellutil
from azurelinuxagent.common.utils.shellutil import CommandError
from azurelinuxagent.common.utils.textutil import format_exception
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.remote_test import run_remote_test
import http.client as httpclient

from tests_e2e.tests.lib.retry import retry_if_false, retry

ROOT_USER = 'root'
WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
WIRESERVER_IP = '168.63.129.16'
VERSIONS_PATH = '/?comp=versions'
FIREWALL_PERIOD = 60


class FirewallRules(object):
    # -D deletes the specific rule in the iptable chain
    DELETE_COMMAND = "-D"

    # -C checks if a specific rule exists
    CHECK_COMMAND = "-C"


def get_wireserver_ip() -> str:
    try:
        with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
            wireserver_ip = f.read()
    except Exception:
        wireserver_ip = WIRESERVER_IP
    return wireserver_ip


def switch_user(user: str) -> None:
    """
    This function switches the function to a given user
    """
    try:
        uid = pwd.getpwnam(user)[2]
        log.info("uid:%s and user name:%s", uid, user)
        os.seteuid(uid)
    except Exception as e:
        raise Exception("Error -- failed to switch user to {0} : Failed with exception {1}".format(user, e))


def get_root_accept_rule_command(command: str) -> List[str]:
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp', '-m',
            'owner',
            '--uid-owner',
            '0', '-j', 'ACCEPT', '-w']


def get_non_root_accept_rule_command(command: str) -> List[str]:
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp',
            '--destination-port', '53', '-j',
            'ACCEPT', '-w']


def get_non_root_drop_rule_command(command: str) -> List[str]:
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp', '-m',
            'conntrack', '--ctstate',
            'INVALID,NEW', '-j', 'DROP', '-w']


def execute_cmd(cmd: List[str]):
    """
    Note: The shellutil.run_command return stdout if exit_code=0, otherwise returns commanderror
    """
    try:
        stdout = shellutil.run_command(cmd)
    except CommandError as e:
        return e.returncode, e.stdout, e.stderr
    return 0, stdout, ""


def check_if_iptable_rule_is_available(full_command: List[str]) -> bool:
    """
    This function is used to check if given rule is present in iptable rule set
    "-C" return exit code 0 if the rule is available.
    """
    exit_code, _, _ = execute_cmd(full_command)
    if exit_code == 0:
        return True
    return False


def print_current_iptable_rules():
    """
    This function prints the current iptable rules
    """
    try:
        cmd = ['sudo', 'iptables', '-L', 'OUTPUT', '-t', 'security', '-nxv']
        exit_code, stdout, stderr = execute_cmd(cmd)
        if exit_code != 0:
            log.warning("Warning -- Failed to fetch the ip table rules with error code: %s and error: %s", exit_code, stderr)
        else:
            for line in stdout.splitlines():
                log.info(str(line))
    except Exception as error:
        raise Exception("Error -- Failed to fetch the ip table rule set {0}".format(error))


def get_all_iptable_rule_commands(command: str) -> Tuple[List[str], List[str], List[str]]:
    return get_root_accept_rule_command(command), get_non_root_accept_rule_command(command), get_non_root_drop_rule_command(command)


def verify_all_rules_exist() -> None:
    """
    This function is used to verify all the iptable rules are present in the rule set
    """
    def check_all_iptables() -> bool:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands(FirewallRules.CHECK_COMMAND)
        found: bool = check_if_iptable_rule_is_available(root_accept) and check_if_iptable_rule_is_available(
            non_root_accept) and check_if_iptable_rule_is_available(non_root_drop)
        return found

    log.info("-----Verifying all ip table rules are present in rule set")
    # Agent will re-add rules within OS.EnableFirewallPeriod, So waiting that time + some buffer
    found: bool = retry_if_false(check_all_iptables, attempts=2, delay=FIREWALL_PERIOD+30)

    if not found:
        fail("IP table rules missing in rule set.\n Current iptable rules:\n {0}".format(
            print_current_iptable_rules()))

    log.info("verified All ip table rules are present in rule set")


def verify_rules_deleted_successfully(commands: List[List[str]] = None) -> None:
    """
    This function is used to verify if provided rule or all(if not specified) iptable rules are deleted successfully.
    """
    log.info("-----Verifying requested rules deleted successfully")

    if commands is None:
        commands = []

    if not commands:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands("-C")
        commands.extend([root_accept, non_root_accept, non_root_drop])

    # "-C" return error code 1 when not available which is expected after deletion
    for command in commands:
        if not check_if_iptable_rule_is_available(command):
            pass
        else:
            raise Exception("Deletion of ip table rules not successful\n.Current ip table rules:\n" + print_current_iptable_rules())

    log.info("ip table rules deleted successfully \n %s", commands)


def delete_iptable_rules(commands: List[List[str]] = None) -> None:
    """
    This function is used to delete the provided rule or all(if not specified) iptable rules
    """
    if commands is None:
        commands = []
    if not commands:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands(FirewallRules.CHECK_COMMAND)
        commands.extend([root_accept, non_root_accept, non_root_drop])

    log.info("-----Deleting ip table rules \n %s", commands)

    try:
        cmd = None
        for command in commands:
            cmd = command
            retry(lambda: execute_cmd(cmd=cmd), attempts=3)
    except Exception as e:
        raise Exception("Error -- Failed to Delete the ip table rule set {0}".format(e))

    log.info("Success --Deletion of ip table rule")


def verify_dns_tcp_to_wireserver_is_allowed(user: str) -> None:
    """
    This function is used to verify if tcp to wireserver is allowed for the given user
    """
    log.info("-----Verifying DNS tcp to wireserver is allowed")
    switch_user(user)
    try:
        socket.create_connection((get_wireserver_ip(), 53), timeout=30)
    except Exception as e:
        raise Exception(
            "Error -- while using DNS TCP request as user:({0}), make sure the firewall rules are set correctly {1}".format(user,
                e))

    log.info("Success -- can connect to wireserver port 53 using TCP as a user:(%s)", user)


def verify_dns_tcp_to_wireserver_is_blocked(user: str) -> None:
    """
    This function is used to verify if tcp to wireserver is blocked for given user
    """
    log.info("-----Verifying DNS tcp to wireserver is blocked")
    switch_user(user)
    try:
        socket.create_connection((get_wireserver_ip(), 53), timeout=10)
        raise Exception("Error -- unprivileged user:({0}) could connect to wireserver port 53 using TCP".format(user))
    except Exception as e:
        # Expected timeout if unprivileged user reaches wireserver
        if isinstance(e, socket.timeout):
            log.info("Success -- unprivileged user:(%s) access to wireserver port 53 using TCP is blocked", user)
        else:
            raise Exception("Unexpected error while connecting to wireserver: {0}".format(format_exception(e)))


def verify_http_to_wireserver_blocked(user: str) -> None:
    """
     This function is used to verify if http to wireserver is blocked for the given user
    """
    log.info("-----Verifying http request to wireserver is blocked")
    switch_user(user)
    try:
        client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=10)
    except Exception as e:
        raise Exception("Error -- failed to create HTTP connection with user: {0} \n {1}".format(user, e))

    try:
        blocked = False
        client.request('GET', VERSIONS_PATH)
    except Exception as e:
        # if we get timeout exception, it means the request is blocked
        if isinstance(e, socket.timeout):
            blocked = True
        else:
            raise Exception("Unexpected error while connecting to wireserver: {0}".format(format_exception(e)))

    if not blocked:
        raise Exception("Error -- unprivileged user:({0}) could connect to wireserver, make sure the firewall rules are set correctly".format(user))

    log.info("Success -- unprivileged user:(%s) access to wireserver is blocked", user)


def verify_http_to_wireserver_allowed(user: str) -> None:
    """
    This function is used to verify if http to wireserver is allowed for the given user
    """
    log.info("-----Verifying http request to wireserver is allowed")
    switch_user(user)
    try:
        client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=30)
    except Exception as e:
        raise Exception("Error -- failed to create HTTP connection with user:{0} \n {1}".format(user, e))

    try:
        client.request('GET', VERSIONS_PATH)
    except Exception as e:
        # if we get exception, it means the request is failed to connect
        raise Exception("Error -- unprivileged user:({0}) access to wireserver failed:\n {1}".format(user, e))

    log.info("Success -- privileged user:(%s) access to wireserver is allowed", user)


def verify_non_root_accept_rule():
    """
    This function verifies the non root accept rule and make sure it is re added by agent after deletion
    """
    log.info("-----Verifying non root accept rule behavior")
    log.info("Before deleting the non root accept rule , ensure a non root user can do a tcp to wireserver but cannot do a http request")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    log.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    shellutil.run_command(stop_agent)

    # deleting non root accept rule
    non_root_accept_delete_cmd = get_non_root_accept_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([non_root_accept_delete_cmd])
    # verifying deletion successful
    non_root_accept_check_cmd = get_non_root_accept_rule_command(FirewallRules.CHECK_COMMAND)
    verify_rules_deleted_successfully([non_root_accept_check_cmd])

    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    log.info("After deleting the non root accept rule , ensure a non root user cannot do a tcp to wireserver request")
    verify_dns_tcp_to_wireserver_is_blocked(NON_ROOT_USER)

    switch_user(ROOT_USER)
    # restart the agent to re-add the deleted rules
    log.info("Restart Guest Agent service to re-add the deleted rules")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    shellutil.run_command(start_agent)

    verify_all_rules_exist()
    log.info("** Current IP table rules \n")
    print_current_iptable_rules()

    log.info("After appending the rule back , ensure a non root user can do a tcp to wireserver but cannot do a http request\n")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    log.info("Ensuring missing rules are re-added by the running agent")
    # deleting non root accept rule
    non_root_accept_delete_cmd = get_non_root_accept_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([non_root_accept_delete_cmd])

    verify_all_rules_exist()
    log.info("** Current IP table rules \n")
    print_current_iptable_rules()

    log.info("non root accept rule verified successfully\n")


def verify_root_accept_rule():
    """
    This function verifies the root accept rule and make sure it is re added by agent after deletion
    """
    log.info("-----Verifying root accept rule behavior")
    log.info("Before deleting the root accept rule , ensure a root user can do a http request but non root user cannot")
    verify_http_to_wireserver_allowed(ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    log.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    shellutil.run_command(stop_agent)

    # deleting root accept rule
    root_accept_delete_cmd = get_root_accept_rule_command(FirewallRules.DELETE_COMMAND)
    # deleting drop rule too otherwise after restart, the daemon will go into loop since it cannot connect to wireserver. This would block the agent initialization
    drop_delete_cmd = get_non_root_drop_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([root_accept_delete_cmd, drop_delete_cmd])
    # verifying deletion successful
    root_accept_check_cmd = get_root_accept_rule_command(FirewallRules.CHECK_COMMAND)
    drop_check_cmd = get_non_root_drop_rule_command(FirewallRules.CHECK_COMMAND)
    verify_rules_deleted_successfully([root_accept_check_cmd, drop_check_cmd])

    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    # restart the agent to re-add the deleted rules
    log.info("Restart Guest Agent service to re-add the deleted rules")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    shellutil.run_command(start_agent)

    verify_all_rules_exist()
    log.info("** Current IP table rules \n")
    print_current_iptable_rules()

    log.info("After appending the rule back , ensure a root user can do a http request but non root user cannot")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)
    verify_http_to_wireserver_allowed(ROOT_USER)

    log.info("Ensuring missing rules are re-added by the running agent")
    # deleting root accept rule
    root_accept_delete_cmd = get_root_accept_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([root_accept_delete_cmd])

    verify_all_rules_exist()
    log.info("** Current IP table rules \n")
    print_current_iptable_rules()

    log.info("root accept rule verified successfully\n")


def verify_non_root_dcp_rule():
    """
    This function verifies drop rule and make sure it is re added by agent after deletion
    """
    log.info("-----Verifying non root drop rule behavior")
    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    log.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    shellutil.run_command(stop_agent)

    # deleting non root delete rule
    non_root_drop_delete_cmd = get_non_root_drop_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([non_root_drop_delete_cmd])
    # verifying deletion successful
    non_root_drop_check_cmd = get_non_root_drop_rule_command(FirewallRules.CHECK_COMMAND)
    verify_rules_deleted_successfully([non_root_drop_check_cmd])

    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    log.info("After deleting the non root drop rule, ensure a non root user can do http request to wireserver")
    verify_http_to_wireserver_allowed(NON_ROOT_USER)

    # restart the agent to re-add the deleted rules
    log.info("Restart Guest Agent service to re-add the deleted rules")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    shellutil.run_command(start_agent)

    verify_all_rules_exist()
    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    log.info("After appending the rule back , ensure a non root user can do a tcp to wireserver but cannot do a http request")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)
    verify_http_to_wireserver_allowed(ROOT_USER)

    log.info("Ensuring missing rules are re-added by the running agent")
    # deleting non root delete rule
    non_root_drop_delete_cmd = get_non_root_drop_rule_command(FirewallRules.DELETE_COMMAND)
    delete_iptable_rules([non_root_drop_delete_cmd])

    verify_all_rules_exist()
    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    log.info("non root drop rule verified successfully\n")


def prepare_agent():
    log.info("Executing script update-waagent-conf to enable agent firewall config flag")
    # Changing the firewall period from default 5 mins to 1 min, so that test won't wait for that long to verify rules
    shellutil.run_command(["update-waagent-conf", "OS.EnableFirewall=y", f"OS.EnableFirewallPeriod={FIREWALL_PERIOD}"])
    log.info("Successfully enabled agent firewall config flag")


def main():
    prepare_agent()
    log.info("** Current IP table rules\n")
    print_current_iptable_rules()

    verify_all_rules_exist()

    verify_non_root_accept_rule()
    verify_root_accept_rule()
    verify_non_root_dcp_rule()


parser = argparse.ArgumentParser()
parser.add_argument('-u', '--user', required=True, help="Non root user")
args = parser.parse_args()
NON_ROOT_USER = args.user
run_remote_test(main)

