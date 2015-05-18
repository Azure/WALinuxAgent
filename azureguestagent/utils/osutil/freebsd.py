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
# Requires Python 2.4+ and Openssl 1.0+
#

import platform
import os
import re
import pwd
import shutil
import tempfile
import subprocess
import socket
import array
import struct
import fcntl
import time
import base64
import azureguestagent.logger as logger
import azureguestagent.utils.fileutil as fileutil
import azureguestagent.utils.shellutil as shellutil
import azureguestagent.utils.textutil as textutil
from azureguestagent.utils.osutil.default import DefaultOSUtil
   
class FreeBSDOSUtil(DefaultOSUtil):
    def __init__(self):
        self.scsiConfigured = False

    def SetScsiDiskTimeout(self, timeout):
        if scsiConfigured:
            return
        shellutil.Run("sysctl kern.cam.da.default_timeout=" + timeout)
        self.scsiConfigured = True
