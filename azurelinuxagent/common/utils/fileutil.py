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
# Requires Python 2.6+ and Openssl 1.0+
#

"""
File operation util functions
"""

import errno as errno # pylint: disable=C0414
import glob
import os
import pwd
import re
import shutil

import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.textutil as textutil

from azurelinuxagent.common.future import ustr

KNOWN_IOERRORS = [
    errno.EIO,          # I/O error
    errno.ENOMEM,       # Out of memory
    errno.ENFILE,       # File table overflow
    errno.EMFILE,       # Too many open files
    errno.ENOSPC,       # Out of space
    errno.ENAMETOOLONG, # Name too long
    errno.ELOOP,        # Too many symbolic links encountered
    121                 # Remote I/O error (errno.EREMOTEIO -- not present in all Python 2.7+)
]


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
            # remove bom on bytes data before it is converted into string.
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
    head, tail = os.path.split(path) # pylint: disable=W0612
    return tail


def get_line_startingwith(prefix, filepath):
    """
    Return line from 'filepath' if the line startswith 'prefix'
    """
    for line in read_file(filepath).split('\n'):
        if line.startswith(prefix):
            return line
    return None


def mkdir(dirpath, mode=None, owner=None):
    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)
    if mode is not None:
        chmod(dirpath, mode)
    if owner is not None:
        chowner(dirpath, owner)


def chowner(path, owner):
    if not os.path.exists(path):
        logger.error("Path does not exist: {0}".format(path))
    else:
        owner_info = pwd.getpwnam(owner)
        os.chown(path, owner_info[2], owner_info[3])


def chmod(path, mode):
    if not os.path.exists(path):
        logger.error("Path does not exist: {0}".format(path))
    else:
        os.chmod(path, mode)


def rm_files(*args):
    for paths in args:
        # find all possible file paths
        for path in glob.glob(paths):
            if os.path.isfile(path):
                os.remove(path)


def rm_dirs(*args):
    """
    Remove the contents of each directory
    """
    for p in args: # pylint: disable=C0103
        if not os.path.isdir(p):
            continue

        for pp in os.listdir(p): # pylint: disable=C0103
            path = os.path.join(p, pp)
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)


def trim_ext(path, ext):
    if not ext.startswith("."):
        ext = "." + ext
    return path.split(ext)[0] if path.endswith(ext) else path


def update_conf_file(path, line_start, val, chk_err=False):
    conf = []
    if not os.path.isfile(path) and chk_err:
        raise IOError("Can't find config file:{0}".format(path))
    conf = read_file(path).split('\n')
    conf = [x for x in conf
            if x is not None and len(x) > 0 and not x.startswith(line_start)]
    conf.append(val)
    write_file(path, '\n'.join(conf) + '\n')


def search_file(target_dir_name, target_file_name):
    for root, dirs, files in os.walk(target_dir_name): # pylint: disable=W0612
        for file_name in files:
            if file_name == target_file_name:
                return os.path.join(root, file_name)
    return None


def chmod_tree(path, mode):
    for root, dirs, files in os.walk(path): # pylint: disable=W0612
        for file_name in files:
            os.chmod(os.path.join(root, file_name), mode)


def findstr_in_file(file_path, line_str):
    """
    Return True if the line is in the file; False otherwise.
    (Trailing whitespace is ignored.)
    """
    try:
        with open(file_path, 'r') as fh: # pylint: disable=C0103
            for line in fh.readlines():
                if line_str == line.rstrip():
                    return True
    except Exception:
        # swallow exception
        pass
    return False


def findre_in_file(file_path, line_re):
    """
    Return match object if found in file.
    """
    try:
        with open(file_path, 'r') as fh: # pylint: disable=C0103
            pattern = re.compile(line_re)
            for line in fh.readlines():
                match = re.search(pattern, line)
                if match:
                    return match
    except: # pylint: disable=W0702
        pass

    return None


def get_all_files(root_path):
    """
    Find all files under the given root path
    """
    result = []
    for root, dirs, files in os.walk(root_path): # pylint: disable=W0612
        result.extend([os.path.join(root, file) for file in files]) # pylint: disable=redefined-builtin

    return result


def clean_ioerror(e, paths=[]): # pylint: disable=W0102,C0103
    """
    Clean-up possibly bad files and directories after an IO error.
    The code ignores *all* errors since disk state may be unhealthy.
    """
    if isinstance(e, IOError) and e.errno in KNOWN_IOERRORS:
        for path in paths:
            if path is None:
                continue

            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
            except Exception:
                # swallow exception
                pass
