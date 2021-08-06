import os
import pwd
import re
import subprocess
import sys

if sys.version_info[0]== 3:
    import http.client as httpclient
elif sys.version_info[0] == 2:
    import httplib as httpclient

FIREWALL_USER = 'edp'
WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
VERSIONS_PATH = '/?comp=versions'

AGENT_CONFIG_FILE = '/etc/waagent.conf'
OS_ENABLE_FIREWALL_RX = r'OS.EnableFirewall\s*=\s*(\S+)'


def is_firewall_enabled():
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


def main():
    if not is_firewall_enabled():
        print("The firewall is not enabled, skipping checks")
        sys.exit(0)

    try:
        with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
            wireserver_ip = f.read()
    except Exception as e:
        print("unable to read wireserver ip: {0}".format(e))
        sys.exit(1)

    try:
        uid = pwd.getpwnam(FIREWALL_USER)[2]
        os.seteuid(uid)
    except Exception as e:
        print("Error -- failed to switch users: {0}".format(e))
        sys.exit(1)

    try:
        client = httpclient.HTTPConnection(wireserver_ip, timeout=1)
    except Exception as e:
        print("Error -- failed to create HTTP connection: {0}".format(e))
        sys.exit(1)

    try:
        client.request('GET', VERSIONS_PATH)
        success = True
    except Exception as e:
        success = False

    if success:
        print("Error -- user could connect to wireserver")
        sys.exit(1)

    print("Success -- user access to wireserver is blocked")
    sys.exit(0)


if __name__ == "__main__":
    main()
