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
# Utility to fetch the goal state.
#
import argparse
import os.path
import re
import subprocess
import sys
import tempfile
import time

from http import client
from typing import Dict, List
from urllib.parse import urlparse
from xml.dom import minidom


verbose: bool = False


def _get(url: str, headers: Dict[str, str], tries: int, timeout: int, delay: int) -> str:
    """
    Issues an HTTP GET request using the given 'url'; returns the response.
    """
    if verbose:
        print(f"\n{url}\n\n")

    p = urlparse(url)
    relative_uri = p.path
    if p.fragment:
        relative_uri = f"{relative_uri}#{p.fragment}"
    if p.query:
        relative_uri = f"{relative_uri}?{p.query}"

    for i in range(tries):
        try:
            connection = client.HTTPConnection(p.hostname, p.port, timeout=timeout)
            try:
                connection.request("GET", url=relative_uri, headers=headers)
                response = connection.getresponse()
                content = response.read().decode("utf-8")
                if response.status != 200:
                    raise Exception(f"{response.reason} - {content}")
                return content
            finally:
                connection.close()
        except Exception as exception:
            print(f"GET {url} failed: {exception}", file=sys.stderr)
        if i < tries - 1:
            print(f"Retrying in {delay} seconds...", file=sys.stderr)
            time.sleep(delay)
    raise Exception(f"GET {url} failed after {tries} tries")


def _get_goal_state(endpoint: str, tries: int, timeout: int, delay: int) -> str:
    """
    Issues an HTTP GET request to retrieve the goal state.
    """
    return _get(url=f"http://{endpoint}:80/machine/?comp=goalstate", headers=_get_wireserver_request_headers(request_encryption=False, key_location=None), tries=tries, timeout=timeout, delay=delay)


def _get_wireserver_request_headers(request_encryption: bool, key_location) -> Dict[str, str]:
    """
    Returns the headers needed for requests to the WireServer endpoint. If 'request_encryption' is True, adds the Transport certificate to the headers.
    """
    headers = {
        "x-ms-agent-name": "WALinuxAgent",
        "x-ms-version": "2012-11-30"
    }
    if request_encryption:
        key = ""
        with open(os.path.join(key_location, "TransportCert.pem"), mode="rt") as f:
            for line in f:
                if not line.startswith("----"):
                    key += line.rstrip()
        headers.update({
            "x-ms-cipher-name": "AES128_CBC",
            "x-ms-guest-agent-public-x509-cert": key
        })
    return headers


def _get_vm_settings(endpoint: str, goal_state_xml: str, tries: int, timeout: int, delay: int) -> str:
    """
    Issues an HTTP GET request to retrieve the VmSettings.
    """
    headers = {
        "x-ms-version": "2015-09-01",
        "x-ms-containerid": _get_elements_by_tag_name(goal_state_xml, "ContainerId")[0],
        "x-ms-host-config-name": _get_elements_by_tag_name(goal_state_xml, "ConfigName")[0],
        "x-ms-client-correlationid": "12345678-9012-3456-7890-123456789012"
    }

    return _get(url=f"http://{endpoint}:32526/vmSettings", headers=headers, tries=tries, timeout=timeout, delay=delay)


def _get_elements_by_tag_name(xml: str, tag: str) -> List[str]:
    """
    Retrieves a list of all the elements matching the given tag in the given XML.
    """
    root = minidom.parseString(xml)
    elements = root.getElementsByTagName(tag)
    if len(elements) == 0:
        raise Exception(f"Can't find {tag}")
    return list(map(lambda e: e.childNodes[0].data if len(e.childNodes) == 1 and e.childNodes[0].nodeType == minidom.Node.TEXT_NODE else e.toxml(), elements))


def _run_command(command: str, command_input: str) -> str:
    """
    Executes a command and returns the stdout.
    """
    return subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ).communicate(input=command_input.encode())[0].decode()


def _extract_certificates(data: str, key_location: str, output_location: str) -> None:
    """
    Extracts the certificates from the WireServer response and writes them to *.crt and *.prv files in the given 'output_location'. The 'key_location'
    specifies the path to the Transport certificate.
    """
    #
    # Decrypt the data returned by the WireServer (which is a PFX package) and convert it into a PEM package.
    #
    pem_data = _run_command(
        f'openssl cms -decrypt -inkey {os.path.join(key_location, "TransportPrivate.pem")} -recip {os.path.join(key_location, "TransportCert.pem")} | openssl pkcs12 -nodes -password pass: -nomacver',
        command_input=f'MIME-Version:1.0\nContent-Disposition: attachment\nContent-Type: application/x-pkcs7-mime\nContent-Transfer-Encoding: base64\n\n{data}'
    )

    #
    # Split the PEM data into individual keys and certificates
    #
    pem_data_lines = pem_data.splitlines()
    keys, certificates = [], []
    start, end = 0, 0
    while end < len(pem_data_lines):
        if re.match(r'[-]+END.*KEY[-]+', pem_data_lines[end]):
            keys.append((start, end))
            start = end + 1
        elif re.match(r'[-]+END.*CERTIFICATE[-]+', pem_data_lines[end]):
            certificates.append((start, end))
            start = end + 1
        end += 1

    #
    # Write each certificates to a *.crt file using the corresponding thumbprint as name; keep a map of thumbprints indexed by public key in
    # order to associate each private key with its corresponding thumbprint.
    #
    thumbprints_by_public_key = {}  # map of thumbprints indexed by the corresponding public key

    for c in certificates:
        certificate_data = "\n".join(pem_data_lines[c[0] : c[1] + 1]) + "\n"
        thumbprint = _run_command('openssl x509 -fingerprint -noout', command_input=certificate_data)
        thumbprint = thumbprint.rstrip().split('=')[1].replace(':', '').upper()  # the fingerprint looks like 'SHA1 Fingerprint=DF:94:08:08:B0:BB:78:23:49:2E:28:E2:E2:33:86:0C:DD:31:75:88'
        public_key = _run_command('openssl x509 -pubkey -noout', command_input=certificate_data)
        thumbprints_by_public_key[public_key] = thumbprint
        certificate_path = os.path.join(output_location, f'{thumbprint}.crt')
        with open(certificate_path, "wt") as f:
            f.write(certificate_data)
        print(certificate_path)

    #
    # Write each private key to a *.prv file using the corresponding thumbprint as name.
    #
    for k in keys:
        key_data = "\n".join(pem_data_lines[k[0] : k[1] + 1])
        public_key = _run_command('openssl rsa -pubout', command_input=key_data)
        thumbprint = thumbprints_by_public_key.get(public_key)
        if thumbprint is None:
            print("WARNING: Skipping private key with no associated certificate", file=sys.stderr)
            continue
        key_path = os.path.join(output_location, f'{thumbprint}.prv')
        with open(key_path, "wt") as f:
            f.write(key_data)
        print(key_path)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Display the current goal state.',
        epilog="""
Displays the goal state object.
Use the --certificates, --extensions, '--hosting-environment, --remote-access, and --shared option to display the corresponding sub-object. 
Use the --tag option to display only the XML elements matching that tag.
Use the --vmsettings to display the VmSettings. Note that this is a JSON document, not an XML document

Examples:

    * get_goal_state.py
    * get_goal_state.py --tag Incarnation
    * get_goal_state.py --extensions
    * get_goal_state.py --certificates --expand /tmp    
    * get_goal_state.py --vmsettings    
""")
    parser.add_argument('--delay', required=False, default=6, type=int, help="Delay in seconds between retries of WireServer requests.")
    parser.add_argument('--endpoint', required=False, default="168.63.129.16", help="IP address for the WireServer endpoint.")
    parser.add_argument('--expand', nargs="?", const="", required=False, help="When used with --certificates, expands the WireServer response into *.crt and *.prv PEM files. If a value is given, files are created under that path, otherwise a temporary directory is used.")
    parser.add_argument('--tag', required=False, default=None, help="Outputs only the XML elements that match the tag.")
    parser.add_argument('--tries', required=False, default=3, type=int, help="Number of times to attempt WireServer requests.")
    parser.add_argument('--timeout', required=False, default=10, type=int, help="Timeout in seconds for WireServer requests.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output.')
    parser.add_argument('--waagent', required=False, default="/var/lib/waagent", help="Location of the Transport certificate for WireServer requests.")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--certificates', action='store_true', help='Fetch the Certificates for the goal state')
    group.add_argument('--extensions', action='store_true', help='Fetch the ExtensionsConfig for the goal state')
    group.add_argument('--hosting-environment', action='store_true', help='Fetch the HostingEnvironmentConfig for the goal state')
    group.add_argument('--remote-access', action='store_true', help='Fetch the RemoteAccessInfo for the goal state')
    group.add_argument('--shared', action='store_true', help='Fetch the SharedConfig for the goal state')
    group.add_argument('--vmsettings', action='store_true', help='Fetch the VmSettings')

    args = parser.parse_args()

    if args.vmsettings:
        if args.tag is not None:
            raise Exception("--vmsettings and --tag are mutually exclusive")

    if args.expand is not None:
        if not args.certificates:
            raise Exception("The --expand option can only be used with --certificates")
        if args.tag is not None:
            raise Exception("--expand and --tag are mutually exclusive")

    if args.verbose:
        global verbose  # pylint: disable=global-statement
        verbose = True

    goal_state = _get_goal_state(endpoint=args.endpoint, tries=args.tries, timeout=args.timeout, delay=args.delay)

    url, headers = None, None
    if args.certificates:
        url = _get_elements_by_tag_name(goal_state, 'Certificates')[0]
        headers = _get_wireserver_request_headers(request_encryption=True, key_location=args.waagent)
    elif args.extensions:
        url = _get_elements_by_tag_name(goal_state, 'ExtensionsConfig')[0]
    elif args.hosting_environment:
        url = _get_elements_by_tag_name(goal_state, 'HostingEnvironmentConfig')[0]
    elif args.remote_access:
        url = _get_elements_by_tag_name(goal_state, 'RemoteAccessInfo')[0]
        headers = _get_wireserver_request_headers(request_encryption=True, key_location=args.waagent)
    elif args.shared:
        url = _get_elements_by_tag_name(goal_state, 'SharedConfig')[0]
    elif args.vmsettings:
        vm_settings = _get_vm_settings(endpoint=args.endpoint, goal_state_xml=goal_state, tries=args.tries, timeout=args.timeout, delay=args.delay)
        print(vm_settings)
        return

    if url is None:
        xml_document = goal_state
    else:
        if headers is None:
            headers = _get_wireserver_request_headers(request_encryption=False, key_location=None)
        xml_document = _get(url, headers=headers, tries=args.tries, timeout=args.timeout, delay=args.delay)

    if args.certificates and args.expand is not None:
        output_location = args.expand if args.expand != '' else tempfile.mkdtemp()
        _extract_certificates(_get_elements_by_tag_name(xml_document, 'Data')[0], key_location=args.waagent, output_location=output_location)
        return

    if args.tag is None:
        print(xml_document)
    else:
        elements = _get_elements_by_tag_name(xml_document, args.tag)
        if len(elements) == 1:
            print(elements[0])
        else:
            print(elements)


if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        print(exception, file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
