from typing import List, Tuple

from assertpy import fail

from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.utils import shellutil
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.retry import retry_if_false

WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
WIRESERVER_IP = '168.63.129.16'
FIREWALL_PERIOD = 30

# helper methods shared by multiple tests

class IPTableRules(object):
    # -D deletes the specific rule in the iptable chain
    DELETE_COMMAND = "-D"

    # -C checks if a specific rule exists
    CHECK_COMMAND = "-C"


class FirewalldRules(object):
    # checks if a specific rule exists
    QUERY_PASSTHROUGH = "--query-passthrough"

    # removes a specific rule
    REMOVE_PASSTHROUGH = "--remove-passthrough"


def get_wireserver_ip() -> str:
    try:
        with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
            wireserver_ip = f.read()
    except Exception:
        wireserver_ip = WIRESERVER_IP
    return wireserver_ip


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


def get_non_root_accept_tcp_firewalld_rule(command):
    return ["firewall-cmd", "--permanent", "--direct", command, "ipv4", "-t", "security", "-A", "OUTPUT", "-d",
            get_wireserver_ip(),
            "-p", "tcp", "--destination-port", "53", "-j", "ACCEPT"]


def get_root_accept_firewalld_rule(command):
    return ["firewall-cmd", "--permanent", "--direct", command, "ipv4", "-t", "security", "-A", "OUTPUT", "-d",
            get_wireserver_ip(),
            "-p", "tcp", "-m", "owner", "--uid-owner", "0", "-j", "ACCEPT"]


def get_non_root_drop_firewalld_rule(command):
    return ["firewall-cmd", "--permanent", "--direct", command, "ipv4", "-t", "security", "-A", "OUTPUT", "-d",
            get_wireserver_ip(),
            "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID,NEW", "-j", "DROP"]


def execute_cmd(cmd: List[str]):
    """
    Note: The shellutil.run_command return stdout if exit_code=0, otherwise returns Exception
    """
    return shellutil.run_command(cmd, track_process=False)


def execute_cmd_return_err_code(cmd: List[str]):
    """
    Note: The shellutil.run_command return err_code plus stdout/stderr
    """
    try:
        stdout = execute_cmd(cmd)
        return 0, stdout
    except Exception as error:
        return -1, ustr(error)


def check_if_iptable_rule_is_available(full_command: List[str]) -> bool:
    """
    This function is used to check if given rule is present in iptable rule set
    "-C" return exit code 0 if the rule is available.
    """
    exit_code, _ = execute_cmd_return_err_code(full_command)
    return exit_code == 0


def print_current_iptable_rules() -> None:
    """
    This function prints the current iptable rules
    """
    try:
        cmd = ["sudo", "iptables", "-t", "security", "-L", "-nxv"]
        stdout = execute_cmd(cmd)
        for line in stdout.splitlines():
            log.info(str(line))
    except Exception as error:
        log.warning("Error -- Failed to fetch the ip table rule set {0}".format(error))


def get_all_iptable_rule_commands(command: str) -> Tuple[List[str], List[str], List[str]]:
    return get_root_accept_rule_command(command), get_non_root_accept_rule_command(command), get_non_root_drop_rule_command(command)


def verify_all_rules_exist() -> None:
    """
    This function is used to verify all the iptable rules are present in the rule set
    """
    def check_all_iptables() -> bool:
        root_accept, non_root_accept, non_root_drop = get_all_iptable_rule_commands(IPTableRules.CHECK_COMMAND)
        found: bool = check_if_iptable_rule_is_available(root_accept) and check_if_iptable_rule_is_available(
            non_root_accept) and check_if_iptable_rule_is_available(non_root_drop)
        return found

    log.info("Verifying all ip table rules are present in rule set")
    # Agent will re-add rules within OS.EnableFirewallPeriod, So waiting that time + some buffer
    found: bool = retry_if_false(check_all_iptables, attempts=2, delay=FIREWALL_PERIOD+15)

    if not found:
        fail("IP table rules missing in rule set.\n Current iptable rules: {0}".format(
            print_current_iptable_rules()))

    log.info("verified All ip table rules are present in rule set")


def firewalld_service_running():
    """
    Checks if firewalld service is running on the VM
    Eg:    firewall-cmd --state
           >   running
    """
    cmd = ["firewall-cmd", "--state"]
    exit_code, output = execute_cmd_return_err_code(cmd)
    if exit_code != 0:
        log.warning("Firewall service not running: {0}".format(output))
    return exit_code == 0 and output.rstrip() == "running"


def get_all_firewalld_rule_commands(command):
    return get_root_accept_firewalld_rule(command), get_non_root_accept_tcp_firewalld_rule(
        command), get_non_root_drop_firewalld_rule(command)


def check_if_firewalld_rule_is_available(command):
    """
    This function is used to check if given firewalld rule is present in rule set
    --query-passthrough return exit code 0 if the rule is available
    """
    exit_code, _ = execute_cmd_return_err_code(command)
    if exit_code == 0:
        return True
    return False


def verify_all_firewalld_rules_exist():
    """
    This function is used to verify all the firewalld rules are present in the rule set
    """

    def check_all_firewalld_rules():
        root_accept, non_root_accept, non_root_drop = get_all_firewalld_rule_commands(FirewalldRules.QUERY_PASSTHROUGH)
        found = check_if_firewalld_rule_is_available(root_accept) and check_if_firewalld_rule_is_available(
            non_root_accept) and check_if_firewalld_rule_is_available(non_root_drop)
        return found

    log.info("Verifying all firewalld rules are present in rule set")
    found = retry_if_false(check_all_firewalld_rules, attempts=2)

    if not found:
        fail("Firewalld rules missing in rule set. {0}".format(
            print_current_firewalld_rules()))

    print_current_firewalld_rules()
    log.info("verified All firewalld rules are present in rule set")


def print_current_firewalld_rules():
    """
    This function prints the current firewalld rules
    """
    try:
        cmd = ["firewall-cmd", "--permanent", "--direct", "--get-all-passthroughs"]
        exit_code, stdout = execute_cmd_return_err_code(cmd)
        if exit_code != 0:
            log.warning("Warning -- Failed to fetch firewalld rules with error code: %s and error: %s", exit_code,
                        stdout)
        else:
            log.info("Current firewalld rules:")
            for line in stdout.splitlines():
                log.info(str(line))
    except Exception as error:
        raise Exception("Error -- Failed to fetch the firewalld rule set {0}".format(error))
