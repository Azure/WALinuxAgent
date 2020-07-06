# Copyright 2020 Microsoft Corporation
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
# Requires Python 2.6+ and Openssl 1.0+
#

import zipfile
import json

from tests.tools import load_bin_data, load_data
from io import BytesIO

from tests.protocol import mockwiredata_filenames

def data_files_to_fetcher(data_files):
    fetcher = {}

    def delay_load(func, filename):
        return lambda: None if not filename else func(filename)

    for key, value in data_files.items():

        if value != None and value.endswith(".zip"):
            fetcher[key] = delay_load(load_bin_data, value)
            continue

        fetcher[key] = delay_load(load_data, value)

    return fetcher

def generate_ext_fetcher_func(manifest, extra_files=None):

    def ext_fetcher_func():
        zip_file_buffer = BytesIO()

        with zipfile.ZipFile(zip_file_buffer, "w", zipfile.ZIP_DEFLATED, False) as file:

            file.writestr("HandlerManifest.json", json.dumps(manifest))

            if extra_files != None:
                for key, value in extra_files.items():
                    file.writestr(key, value)

        return zip_file_buffer.getvalue()

    return ext_fetcher_func



DEFAULT_FETCHER = data_files_to_fetcher(mockwiredata_filenames.DATA_FILE)