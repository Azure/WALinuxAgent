# Microsoft Azure Linux Agent
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

"""
File operation util functions
"""

import os
import re
import shutil
import pwd
import tempfile
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.utils.textutil as textutil

def read_file(filepath, asbin=False, remove_bom=False, encoding='utf-8'):
    """
    Read and return contents of 'filepath'.
    """
    mode = 'rb'
    with open(filepath, mode) as in_file:
        data = in_file.read()
        if data is None:
            return None

        if asbin:
            return data

        if remove_bom:
            #Remove bom on bytes data before it is converted into string.
            data = textutil.remove_bom(data)
        data = ustr(data, encoding=encoding)
        return data

def write_file(filepath, contents, asbin=False, encoding='utf-8', append=False):
    """
    Write 'contents' to 'filepath'.
    """
    mode = "ab" if append else "wb"
    data = contents
    if not asbin:
        data = contents.encode(encoding)
    with open(filepath, mode) as out_file:
        out_file.write(data)

def append_file(filepath, contents, asbin=False, encoding='utf-8'):
    """
    Append 'contents' to 'filepath'.
    """
    write_file(filepath, contents, asbin=asbin, encoding=encoding, append=True)


def base_name(path):
    head, tail = os.path.split(path)
    return tail

def get_line_startingwith(prefix, filepath):
    """
    Return line from 'filepath' if the line startswith 'prefix'
    """
    for line in read_file(filepath).split('\n'):
        if line.startswith(prefix):
            return line
    return None

#End File operation util functions

def mkdir(dirpath, mode=None, owner=None):
    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)
    if mode is not None:
        chmod(dirpath, mode)
    if owner is not None:
        chowner(dirpath, owner)

def chowner(path, owner):
    owner_info = pwd.getpwnam(owner)
    os.chown(path, owner_info[2], owner_info[3])

def chmod(path, mode):
    os.chmod(path, mode)

def rm_files(*args):
    for path in args:
        if os.path.isfile(path):
            os.remove(path)

def rm_dirs(*args):
    """
    Remove all the contents under the directry
    """
    for dir_name in args:
        if os.path.isdir(dir_name):
            for item in os.listdir(dir_name):
                path = os.path.join(dir_name, item)
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)

def update_conf_file(path, line_start, val, chk_err=False):
    conf = []
    if not os.path.isfile(path) and chk_err:
        raise IOError("Can't find config file:{0}".format(path))
    conf = read_file(path).split('\n')
    conf = [x for x in conf if not x.startswith(line_start)]
    conf.append(val)
    write_file(path, '\n'.join(conf))

def search_file(target_dir_name, target_file_name):
    for root, dirs, files in os.walk(target_dir_name):
        for file_name in files:
            if file_name == target_file_name:
                return os.path.join(root, file_name)
    return None

def chmod_tree(path, mode):
    for root, dirs, files in os.walk(path):
        for file_name in files:
            os.chmod(os.path.join(root, file_name), mode)

def findstr_in_file(file_path, pattern_str):
    """
    Return match object if found in file.
    """
    try:
        pattern = re.compile(pattern_str)
        for line in (open(file_path, 'r')).readlines():
            match = re.search(pattern, line)
            if match:
                return match
    except:
        raise

    return None

