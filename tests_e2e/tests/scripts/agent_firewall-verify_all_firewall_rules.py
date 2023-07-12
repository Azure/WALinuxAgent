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
import logging
import os
import pwd
import socket
import subprocess
import sys
import time
import traceback
from typing import List

if sys.version_info[0] == 3:
    import http.client as httpclient
elif sys.version_info[0] == 2:
    import httplib as httpclient  # pylint: disable=E0401

NON_ROOT_USER = 'unknown_user'
ROOT_USER = 'root'
WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
WIRESERVER_URL = '168.63.129.16'
VERSIONS_PATH = '/?comp=versions'


def get_wireserver_ip():
    try:
        with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
            wireserver_ip = f.read()
    except Exception:
        wireserver_ip = WIRESERVER_URL
    return wireserver_ip


def switch_user(user):
    # This function switches the function to a given user
    try:
        uid = pwd.getpwnam(user)[2]
        logging.info("uid:%s and user name:%s", uid, user)
        os.seteuid(uid)
    except Exception as e:
        raise Exception("Error -- failed to switch user to {0} : Failed with exception {1}".format(user, e))


def get_root_accept_rule(command: str):
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp', '-m',
            'owner',
            '--uid-owner',
            '0', '-j', 'ACCEPT', '-w']


def get_non_root_accept_rule(command: str):
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp',
            '--destination-port', '53', '-j',
            'ACCEPT', '-w']


def get_non_root_drop_rule(command: str):
    return ['sudo', 'iptables', '-t', 'security', command, 'OUTPUT', '-d', get_wireserver_ip(), '-p', 'tcp', '-m',
            'conntrack', '--ctstate',
            'INVALID,NEW', '-j', 'DROP', '-w']


def execute_cmd(cmd: List[str]):
    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False)
    stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr


def check_if_iptable_rule_is_available(full_command: List[str]):
    # This function is used to check if given rule is present in iptable rule set
    # "-C" return exit code 0 if the rule is available.
    exit_code, _, _ = execute_cmd(full_command)
    if exit_code == 0:
        return True
    return False


def print_current_iptable_rules():
    # This function prints the current iptable rules
    try:
        cmd = ['sudo', 'iptables', '-L', 'OUTPUT', '-t', 'security', '-nxv']
        exit_code, stdout, stderr = execute_cmd(cmd)
        if exit_code != 0:
            logging.warning("Warning -- Failed to fetch the ip table rules with error code: %s and error: %s", exit_code, stderr)
        else:
            for line in stdout.splitlines():
                logging.info(str(line))
    except Exception as error:
        raise Exception("Error -- Failed to fetch the ip table rule set {0}".format(error))


def get_all_iptable_rule_commands(command: str):
    return get_root_accept_rule(command), get_non_root_accept_rule(command), get_non_root_drop_rule(command)


def verify_all_rules_exist(max_retry: int = 5):
    # This function is used to verify all the iptable rules are present in the rule set
    logging.info("-----Verifying all ip table rules are present in rule set")
    retry: int = 0
    found: bool = False
    while retry < max_retry and not found:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands("-C")
        found = check_if_iptable_rule_is_available(root_accept) and check_if_iptable_rule_is_available(
            non_root_accept) and check_if_iptable_rule_is_available(non_root_drop)

        if not found:
            logging.info("Not all ip table rules are present, retrying in 30 secs.\n")
            time.sleep(30)
        retry += 1

    if not found:
        raise Exception("IP table rules missing in rule set.\n Current iptable rules:\n {0}".format(
            print_current_iptable_rules()))

    logging.info("verified All ip table rules are present in rule set")


def verify_rules_deleted_successfully(commands: List[List[str]] = None):
    # This function is used to verify if provided rule or all(if not specified) iptable rules are deleted successfully.
    logging.info("-----Verifying requested rules deleted successfully")

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

    logging.info("ip table rules deleted successfully \n %s", commands)


def delete_iptable_rules(commands: List[List[str]] = None):
    # This function is used to delete the provided rule or all(if not specified) iptable rules
    if commands is None:
        commands = []
    if not commands:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands("-C")
        commands.extend([root_accept, non_root_accept, non_root_drop])

    logging.info("-----Deleting ip table rules \n %s", commands)

    try:
        for command in commands:
            execute_cmd(command)
    except Exception as e:
        raise Exception("Error -- Failed to Delete the ip table rule set {0}".format(e))

    logging.info("Success --Deletion of ip table rule")


def verify_dns_tcp_to_wireserver_is_allowed(user: str):
    # This function is used to verify if tcp to wireserver is allowed for the given user
    logging.info("-----Verifying DNS tcp to wireserver is allowed")
    switch_user(user)
    try:
        socket.create_connection((get_wireserver_ip(), 53), timeout=10)
    except Exception as e:
        raise Exception(
            "Error -- while using DNS TCP request as user:({0}), make sure the firewall rules are set correctly {1}".format(user,
                e))

    logging.info("Success -- can connect to wireserver port 53 using TCP as a user:(%s)", user)


def verify_dns_tcp_to_wireserver_is_blocked(user: str):
    # This function is used to verify if tcp to wireserver is blocked for given user
    logging.info("-----Verifying DNS tcp to wireserver is blocked")
    switch_user(user)
    try:
        socket.create_connection((get_wireserver_ip(), 53), timeout=10)
        raise Exception("Error -- unprivileged user:({0}) could connect to wireserver port 53 using TCP".format(user))
    except Exception:
        logging.info("Success -- unprivileged user:(%s) access to wireserver port 53 using TCP is blocked", user)


def verify_http_to_wireserver_blocked(user: str):
    # This function is used to verify if http to wireserver is blocked for the given user
    logging.info("-----Verifying http request to wireserver is blocked")
    switch_user(user)
    try:
        client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=1)
    except Exception as e:
        raise Exception("Error -- failed to create HTTP connection with user:{0} \n {1}".format(user, e))

    try:
        blocked = False
        client.request('GET', VERSIONS_PATH)
    except Exception:
        # if we get exception, it means the request is blocked
        blocked = True

    if not blocked:
        raise Exception("Error -- unprivileged user:({0}) could connect to wireserver, make sure the firewall rules are set correctly".format(user))

    logging.info("Success -- unprivileged user:(%s) access to wireserver is blocked", user)


def verify_http_to_wireserver_allowed(user: str):
    # This function is used to verify if http to wireserver is allowed for the given user
    logging.info("-----Verifying http request to wireserver is allowed")
    switch_user(user)
    try:
        client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=1)
    except Exception as e:
        raise Exception("Error -- failed to create HTTP connection with user:{0} \n {1}".format(user, e))

    try:
        client.request('GET', VERSIONS_PATH)
    except Exception as e:
        # if we get exception, it means the request is failed to connect
        raise Exception("Error -- unprivileged user:({0}) access to wireserver failed:\n {1}".format(user, e))

    logging.info("Success -- privileged user:(%s) access to wireserver is allowed", user)


def verify_non_root_accept_rule():
    # This function verifies the non root accept rule and make sure it is re added by agent after deletion
    logging.info("-----Verifying non root accept rule behavior")
    logging.info("Before deleting the non root accept rule , ensure a non root user can do a tcp to wireserver but cannot do a http request")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    logging.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    execute_cmd(stop_agent)

    # deleting non root accept rule
    non_root_accept_delete_cmd = get_non_root_accept_rule("-D")
    delete_iptable_rules([non_root_accept_delete_cmd])
    # verifying deletion successful
    non_root_accept_check_cmd = get_non_root_accept_rule("-C")
    verify_rules_deleted_successfully([non_root_accept_check_cmd])

    logging.info("** Current IP table rules\n")
    print_current_iptable_rules()

    logging.info("After deleting the non root accept rule , ensure a non root user cannot do a tcp to wireserver request")
    verify_dns_tcp_to_wireserver_is_blocked(NON_ROOT_USER)

    switch_user(ROOT_USER)
    # restart the agent to re-add the deleted rules
    logging.info("Restart Guest Agent service")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    execute_cmd(start_agent)

    verify_all_rules_exist()
    logging.info("** Current IP table rules \n")
    print_current_iptable_rules()

    logging.info("After appending the rule back , ensure a non root user can do a tcp to wireserver but cannot do a http request\n")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    logging.info("non root accept rule verified successfully\n")


def verify_root_accept_rule():
    # This function verifies the root accept rule and make sure it is re added by agent after deletion
    logging.info("-----Verifying root accept rule behavior")
    logging.info("Before deleting the root accept rule , ensure a root user can do a http request but non root user cannot")
    verify_http_to_wireserver_allowed(ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)

    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    logging.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    execute_cmd(stop_agent)

    # deleting root accept rule
    root_accept_delete_cmd = get_root_accept_rule("-D")
    # deleting drop rule too otherwise after restart, the daemon will go into loop since it cannot connect to wireserver. This would block the agent initialization
    drop_delete_cmd = get_non_root_drop_rule("-D")
    delete_iptable_rules([root_accept_delete_cmd, drop_delete_cmd])
    # verifying deletion successful
    root_accept_check_cmd = get_root_accept_rule("-C")
    drop_check_cmd = get_non_root_drop_rule("-C")
    verify_rules_deleted_successfully([root_accept_check_cmd, drop_check_cmd])

    logging.info("** Current IP table rules\n")
    print_current_iptable_rules()

    # restart the agent to re-add the deleted rules
    logging.info("Restart Guest Agent service")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    execute_cmd(start_agent)

    verify_all_rules_exist()
    logging.info("** Current IP table rules \n")
    print_current_iptable_rules()

    logging.info("After appending the rule back , ensure a root user can do a http request but non root user cannot")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)
    verify_http_to_wireserver_allowed(ROOT_USER)

    logging.info("root accept rule verified successfully\n")


def verify_non_root_dcp_rule():
    # This function verifies drop rule and make sure it is re added by agent after deletion
    logging.info("-----Verifying non root drop rule behavior")
    # switch to root user required to stop the agent
    switch_user(ROOT_USER)
    # stop the agent, so that it won't re-add rules while checking
    logging.info("Stop Guest Agent service")
    # agent-service is script name and stop is argument
    stop_agent = ["agent-service", "stop"]
    execute_cmd(stop_agent)

    # deleting non root delete rule
    non_root_drop_delete_cmd = get_non_root_drop_rule("-D")
    delete_iptable_rules([non_root_drop_delete_cmd])
    # verifying deletion successful
    non_root_drop_check_cmd = get_non_root_drop_rule("-C")
    verify_rules_deleted_successfully([non_root_drop_check_cmd])

    logging.info("** Current IP table rules\n")
    print_current_iptable_rules()

    logging.info("After deleting the non root drop rule, ensure a non root user can do http request to wireserver")
    verify_http_to_wireserver_allowed(NON_ROOT_USER)

    # restart the agent to re-add the deleted rules
    logging.info("Restart Guest Agent service")
    # agent-service is script name and start is argument
    start_agent = ["agent-service", "start"]
    execute_cmd(start_agent)

    verify_all_rules_exist()
    logging.info("** Current IP table rules\n")
    print_current_iptable_rules()

    logging.info("After appending the rule back , ensure a non root user can do a tcp to wireserver but cannot do a http request")
    verify_dns_tcp_to_wireserver_is_allowed(NON_ROOT_USER)
    verify_http_to_wireserver_blocked(NON_ROOT_USER)
    verify_http_to_wireserver_allowed(ROOT_USER)

    logging.info("non root drop rule verified successfully\n")


try:
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG, stream=sys.stdout)

    # This user would be the non root user
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', required=True)
    args = parser.parse_args()

    NON_ROOT_USER = args.user

    verify_all_rules_exist()

    logging.info("** Current IP table rules\n")
    print_current_iptable_rules()

    verify_non_root_accept_rule()
    verify_root_accept_rule()
    verify_non_root_dcp_rule()

    sys.exit(0)

except Exception as e:
    logging.error("%s:\n%s", e, traceback.format_exc())
    sys.exit(1)
