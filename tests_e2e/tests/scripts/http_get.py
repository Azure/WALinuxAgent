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
# Prints the distro and version of the machine
#
import argparse
import time
import sys

from http import client
from urllib.parse import urlparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', dest="timeout", required=False, default=5)
    parser.add_argument('-r', '--tries', dest="tries", required=False, default=3)
    parser.add_argument('-d', '--delay', dest="delay", required=False, default=5)
    parser.add_argument('url')

    args = parser.parse_args()

    url = args.url
    timeout = int(args.timeout)
    tries = int(args.tries)
    delay = int(args.delay)

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
                connection.request("GET", url=relative_uri)
                response = connection.getresponse()
                content = response.read().decode("utf-8")
                if response.status != 200:
                    raise Exception(f"{response.reason}", content)
                print(content)
                break
            finally:
                connection.close()
        except Exception as exception:
            print(f"GET failed: {exception}", file=sys.stderr)
        if i < tries - 1:
            time.sleep(delay)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
