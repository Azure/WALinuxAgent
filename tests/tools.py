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
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx


import os
import sys
from functools import wraps
from azurelinuxagent.utils.osutil import OSUTIL

parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent)

def simple_file_grep(file_path, search_str):
    for line in open(file_path):
         if search_str in line:
                return line

def mock(target, name, mock):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            origin = getattr(target, name)
            setattr(target, name, mock)
            try:
                result = func(*args, **kwargs)
            except:
                raise
            finally:
                setattr(target, name, origin)
            return result
        return wrapper
    return decorator

class MockFunc(object):
    def __init__(self, name='', retval=None):
        self.name = name
        self.retval = retval

    def __call__(*args, **kwargs):
        self = args[0]
        self.args = args[1:]
        self.kwargs = kwargs
        return self.retval


#Mock osutil so that the test of other part will be os unrelated
OSUTIL.get_lib_dir = MockFunc(retval='/tmp')
OSUTIL.get_ext_log_dir = MockFunc(retval='/tmp/log')
