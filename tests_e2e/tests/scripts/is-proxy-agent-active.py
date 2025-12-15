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
# Script to verify the presence of the Proxy Agent.
#
# When the Proxy Agent manages the WireServer endpoint, it will intercept HTTP request even before they reach the firewall and failed them with 403 (Forbidden).
# Some tests, e.g. those related to firewall, need to be aware of this behavior.
#
# The scripts works by issuing a request for the Versions WireServer API as a non-root user. If azure-proxy-agent.service is active and the request fails with
# 403, we assume that the Proxy Server is managing the WireServer endpoint. Note that the service may be active, but it may not be managing the endpoint, depending
# on its configuration.
#
# If that HTTP request times out, we assume that the request reached the firewall and that the Proxy Agent is not managing the endpoint.
#
# If the request succeeds, or fails with a status other than 403, the configuration of the firewall is incorrect, since non-root should not be able to connect
# to the WireServer.
#
# The script returns an exit code of 0 when the Proxy Agent is managing the endpoint, 1 if it is not managing the endpoint, and 2 if an error occurs.
#
import os
import pwd
import socket
import sys

import http.client as httpclient

from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.shell import run_command, CommandError
from tests_e2e.tests.lib.firewall_manager import get_wireserver_ip

try:
    if os.geteuid() == 0:
        raise Exception("This script should not be run as root.")

    try:
        stdout = run_command(['systemctl', 'is-active', 'azure-proxy-agent.service']).rstrip()
        log.info(f"The azure-proxy-agent.service is active. State: {stdout}")
    except CommandError as e:
        if e.exit_code in [3, 4]:  # 3 == unit is not active, 4 == no such unit
            log.info(f"The azure-proxy-agent.service is not {'active' if e.exit_code == 3 else 'installed'}. ")
            sys.exit(1)
        raise

    try:
        client = httpclient.HTTPConnection(get_wireserver_ip(), timeout=10)
        client.request('GET', '/?comp=versions')
        response = client.getresponse()
        if response.status == 403:
            log.info("The azure-proxy-agent.service is managing the WireServer endpoint")
            sys.exit(0)
        raise Exception(f"Incorrect firewall configuration. Non-root is able to connect to the WireServer. User: {pwd.getpwuid(os.geteuid()).pw_name}. HTTP status: {response.status}. HTTP response: {response.read()}")
    except Exception as e:
        if isinstance(e, socket.timeout):
            log.info("The azure-proxy-agent.service is not managing the WireServer endpoint")
            sys.exit(1)
        raise
except Exception as e:
    log.error(f"{str(e)}")
    sys.exit(2)
