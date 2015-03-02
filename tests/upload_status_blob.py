#!/usr/bin/env python
#
# Copyright 2014 Microsoft Corporation
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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

import os
from env import waagent
"""
To run the test, you need to create a file under the same directory called:
    status_blob_url.py
and defined the following 2 variables like:
    blockBlobUrl="<sas link to a block blob with w/r access>"
    pageBlobUrl="<sas link to a page blob with w/r access>"
"""
from status_blob_url import blockBlobUrl, pageBlobUrl

if __name__ == '__main__':
    waagent.LoggerInit('/dev/stdout', '/dev/null', verbose=True)
    status = "a" * 512
    waagent.UploadStatusBlob(blockBlobUrl, status.encode("utf-8"))
    waagent.UploadStatusBlob(pageBlobUrl, status.encode("utf-8"))
