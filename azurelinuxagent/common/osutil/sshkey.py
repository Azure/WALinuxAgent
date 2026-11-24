#
# Copyright Microsoft Corporation
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

import errno
import os
import stat
import subprocess
import sys
from contextlib import contextmanager

from azurelinuxagent.common import logger
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.future import ustr

_HAS_PASS_FDS = sys.version_info >= (3, 2)


def _legacy_at(name, *args):
    # Python 2 has no dir_fd argument, so use libc rather than change the working directory.
    try:
        import ctypes
        syscall = getattr(ctypes.CDLL(None, use_errno=True), name)
    except (ImportError, AttributeError):
        raise OSUtilError("Descriptor-relative SSH key access is unavailable")
    result = syscall(*(arg.encode(sys.getfilesystemencoding()) if isinstance(arg, ustr) else arg for arg in args))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _at(operation, parent, name, *args):
    if operation in getattr(os, "supports_dir_fd", ()):
        return operation(name, *args, dir_fd=parent)
    if operation is os.rmdir:
        # Each platform defines its own AT_REMOVEDIR value in fcntl.h.
        for platform, flag in (("linux", 0x200), ("freebsd", 0x800), ("openbsd", 0x08)):
            if sys.platform.startswith(platform):
                return _legacy_at("unlinkat", parent, name, flag)
        raise OSUtilError("Directory removal by descriptor is unavailable on {0}".format(sys.platform))
    return _legacy_at(operation.__name__ + "at", parent, name, *args)


# First-time creation in a user-writable directory must not involve a later
# privileged chown. Drop credentials in a fresh interpreter, never in the agent.
_CREATE_AS_ACCOUNT = """\
import errno, os, sys
uid, gid, kind, name, parent_fd = sys.argv[1:]
uid, gid = int(uid), int(gid)
if (os.geteuid(), os.getegid()) != (uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
os.umask(0o077)
os.fchdir(int(parent_fd))
os.close(int(parent_fd))
try:
    if kind == 'directory':
        os.mkdir(name, 0o700)
    elif kind == 'file':
        os.close(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    else:
        raise ValueError("Unknown SSH entry type")
except OSError as error:
    if error.errno != errno.EEXIST:
        raise
    sys.exit(errno.EEXIST)
"""


def _create_as_account(parent, name, account, kind):
    command = [sys.executable, "-E", "-S", "-c", _CREATE_AS_ACCOUNT,
               str(account.pw_uid), str(account.pw_gid), kind, name]
    with open(os.devnull, "r+b") as devnull:
        if _HAS_PASS_FDS and parent > 2:
            command.append(str(parent))
            fd_options = {"pass_fds": (parent,), "stdin": devnull}
        else:
            # Old Python has no pass_fds. Move the directory fd off stdin before
            # starting the interpreter. The shell never evaluates the pathname.
            command = ["/bin/sh", "-c", 'exec "$@" 3<&0 </dev/null', "waagent-ssh-create"] + command + ["3"]
            fd_options = {"stdin": parent}
        process = subprocess.Popen(command, cwd=os.sep, env={"PATH": os.defpath}, stdout=devnull,
                                   stderr=subprocess.PIPE, close_fds=True, **fd_options)
    _, stderr = process.communicate()
    if process.returncode == errno.EEXIST:
        return False
    if process.returncode != 0:
        raise OSUtilError("Cannot create SSH {0} as {1}: {2}".format(
            kind, account.pw_name, ustr(stderr, encoding="utf-8", errors="replace").strip()))
    return True


def _entry_stat(parent, name, flags):
    if os.stat in getattr(os, "supports_dir_fd", ()) and os.stat in getattr(os, "supports_follow_symlinks", ()):
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = _at(os.open, parent, name, flags)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _mkdir_owned(parent, name, account, flags):
    info = os.fstat(parent)
    root_managed = info.st_uid == 0 and not info.st_mode & 0o022
    if os.geteuid() != account.pw_uid and not root_managed:
        return _create_as_account(parent, name, account, "directory")

    # mkdir never replaces an existing entry. The caller reopens and checks
    # the winner even when another process creates the directory first.
    try:
        _at(os.mkdir, parent, name, 0o700)
    except OSError as error:
        if error.errno == errno.EEXIST:
            return False
        raise
    if root_managed and os.geteuid() != account.pw_uid:
        # Some appliances give the account a root-managed home: only root can
        # create .ssh here, and the account cannot substitute the new entry.
        child = _at(os.open, parent, name, flags)
        try:
            if os.fstat(child).st_uid != os.geteuid():
                raise OSUtilError("SSH directory changed during creation: {0}".format(name))
            os.fchown(child, account.pw_uid, account.pw_gid)
        except OSError:
            try:
                if os.path.samestat(_entry_stat(parent, name, flags), os.fstat(child)):
                    _at(os.rmdir, parent, name)
            except (OSError, OSUtilError) as cleanup_error:
                logger.warn("Could not remove unfinished SSH directory {0}: {1}", name, cleanup_error)
            raise
        finally:
            os.close(child)
    return True


def _open_home(home, flags, links_left=40):
    """Open the home one directory at a time.

    Follow links like /home -> /usr/home only when root controls the path to the link.
    """
    fd = os.open(os.sep, flags)
    prefix = os.sep
    trusted = True
    components = [part for part in home.split(os.sep) if part and part != "."]
    try:
        for index, part in enumerate(components):
            info = os.fstat(fd)
            trusted = trusted and info.st_uid == 0 and not info.st_mode & 0o022
            try:
                child = _at(os.open, fd, part, flags)
            except OSError as error:
                if not trusted or not links_left or error.errno not in (errno.ENOTDIR, errno.ELOOP):
                    raise
                target = os.readlink(os.path.join(prefix, part))
                return _open_home(os.path.join(prefix, target, *components[index + 1:]), flags, links_left - 1)
            os.close(fd)
            fd = child
            prefix = os.path.join(prefix, part)
        if os.path.samestat(os.fstat(fd), os.stat(os.sep)):
            raise OSUtilError("The filesystem root is not a valid SSH key home")
        return os.dup(fd)
    finally:
        os.close(fd)


def _checked_key_stream(fd, name, flags, allowed_owners=None):
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSUtilError("SSH key destination is not a singly linked regular file: {0}".format(name))
        if allowed_owners is not None and info.st_uid not in allowed_owners:
            raise OSUtilError("SSH key destination has an unexpected owner: {0}".format(name))
        return os.fdopen(fd, "ab" if flags & os.O_APPEND else "wb")
    except (OSUtilError, IOError, OSError):
        os.close(fd)
        raise


def _open_existing_key(parent, name, flags, allowed_owners):
    try:
        fd = _at(os.open, parent, name, flags)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None
        raise
    return _checked_key_stream(fd, name, flags, allowed_owners)


def _create_key(parent, name, flags):
    fd = _at(os.open, parent, name, flags | os.O_CREAT | os.O_EXCL, 0o600)
    return _checked_key_stream(fd, name, flags)


def _create_public_key(parent, name, flags, account):
    if os.geteuid() != account.pw_uid:
        _create_as_account(parent, name, account, "file")
    else:
        try:
            return _create_key(parent, name, flags)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
    stream = _open_existing_key(parent, name, flags, (account.pw_uid,))
    if stream is None:
        raise OSUtilError("SSH key disappeared during creation: {0}".format(name))
    return stream


@contextmanager
def _key_directory(home, directories, account, flags):
    parent = _open_home(home, flags)
    complete = False
    try:
        if os.fstat(parent).st_uid not in (0, account.pw_uid):
            raise OSUtilError("SSH key home has an unexpected owner")
        for directory in directories:
            created = False
            try:
                child = _at(os.open, parent, directory, flags)
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                created = _mkdir_owned(parent, directory, account, flags)
                child = _at(os.open, parent, directory, flags)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != account.pw_uid:
                raise OSUtilError("SSH key directory has an unexpected owner: {0}".format(directory))
            if created and info.st_gid != account.pw_gid:
                os.fchown(parent, -1, account.pw_gid)
        yield parent
        complete = True
    finally:
        try:
            os.close(parent)
        except OSError as error:
            _cleanup_error(error, complete)


def _cleanup_error(error, complete):
    if complete:
        raise error
    logger.warn("Could not close SSH key resources after an earlier failure: {0}", error)


@contextmanager
def _key_streams():
    files = []
    complete = False
    try:
        yield files
        complete = True
    finally:
        first_error = None
        for stream in files:
            if stream is not None:
                try:
                    stream.close()
                except (IOError, OSError) as error:
                    if first_error is None:
                        first_error = error
        if first_error is not None:
            _cleanup_error(first_error, complete)


@contextmanager
def key_files(home, components, account, keypair=False):
    """Open files under .ssh so callers write to the same files we checked."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSUtilError("SSH key deployment requires no-follow directory opens")
    # A full path could bypass the directory we just checked. Use one name per lookup.
    if not components or any(name in ("", ".", "..") or os.sep in name for name in components):
        raise OSUtilError("Invalid SSH key path components")
    no_follow = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | no_follow
    file_flags = os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | no_follow
    names = [components[-1]]
    allowed_owners = (account.pw_uid,)
    if keypair:
        names.append(components[-1] + ".pub")
        allowed_owners += (os.geteuid(),)
    else:
        file_flags |= os.O_APPEND
    directories = (".ssh",) + components[:-1]
    try:
        with _key_directory(home, directories, account, dir_flags) as parent:
            with _key_streams() as files:
                # Check both existing files before creating or truncating either.
                for name in names:
                    files.append(_open_existing_key(parent, name, file_flags, allowed_owners))
                if keypair:
                    for index, name in enumerate(names):
                        if files[index] is None:
                            files[index] = _create_key(parent, name, file_flags)
                    if os.path.samestat(os.fstat(files[0].fileno()), os.fstat(files[1].fileno())):
                        raise OSUtilError("The private and public SSH key destinations are the same file")
                os.fchmod(parent, 0o700)
                if not keypair:
                    if files[0] is None:
                        files[0] = _create_public_key(parent, names[0], file_flags, account)
                    if os.fstat(files[0].fileno()).st_gid != account.pw_gid:
                        os.fchown(files[0].fileno(), -1, account.pw_gid)
                yield files
    except (IOError, OSError) as error:
        raise OSUtilError("Cannot deploy SSH key at {0}: {1}".format(os.path.join(".ssh", *components), error))
