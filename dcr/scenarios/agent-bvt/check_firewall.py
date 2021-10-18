import os
import pwd
import re
import subprocess
import sys

if sys.version_info[0] == 3:
    import http.client as httpclient
elif sys.version_info[0] == 2:
    import httplib as httpclient

WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
VERSIONS_PATH = '/?comp=versions'

AGENT_CONFIG_FILE = '/etc/waagent.conf'
OS_ENABLE_FIREWALL_RX = r'OS.EnableFirewall\s*=\s*(\S+)'


def __is_firewall_enabled():
    with open(AGENT_CONFIG_FILE, 'r') as config_fh:
        for line in config_fh.readlines():
            if not line.startswith('#'):
                update_match = re.match(OS_ENABLE_FIREWALL_RX, line, re.IGNORECASE)
                if update_match:
                    return update_match.groups()[0].lower() == 'y'

    # The firewall is enabled by default.
    return True


def run(*args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rc = p.wait()
    if rc != 0:
        return False, None
    else:
        o = list(map(lambda s: s.decode('utf-8').strip(), p.stdout.read()))
        return True, o


def check_firewall(username):
    if not __is_firewall_enabled():
        return "The firewall is not enabled, skipping checks"

    with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
        wireserver_ip = f.read()

    uid = pwd.getpwnam(username)[2]
    os.seteuid(uid)

    client = httpclient.HTTPConnection(wireserver_ip, timeout=1)

    try:
        client.request('GET', VERSIONS_PATH)
        success = True
    except Exception as err:
        print(err)
        success = False

    if success:
        raise Exception("Error -- user could connect to wireserver")

    return "Success -- user access to wireserver is blocked"

