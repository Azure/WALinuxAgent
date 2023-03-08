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
# Un-compresses a bz2 file
#
import argparse
import bz2
import shutil
import sys

try:
    parser = argparse.ArgumentParser()
    parser.add_argument('source', help='File to uncompress')
    parser.add_argument('target', help='Output file')

    args = parser.parse_args()

    with bz2.BZ2File(args.source, 'rb') as f_in:
        with open(args.target, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)

sys.exit(0)
