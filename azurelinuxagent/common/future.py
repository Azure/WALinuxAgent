import contextlib
import platform
import sys
import os
import re

# Note broken dependency handling to avoid potential backward
# compatibility issues on different distributions
try:
    import distro  # pylint: disable=E0401
except Exception:
    pass

# pylint: disable=W0105
"""
Add alias for python2 and python3 libs and functions.
""" 
# pylint: enable=W0105

if sys.version_info[0] == 3:
    import http.client as httpclient  # pylint: disable=W0611,import-error
    from urllib.parse import urlparse  # pylint: disable=W0611,import-error,no-name-in-module

    """Rename Python3 str to ustr"""  # pylint: disable=W0105
    ustr = str

    bytebuffer = memoryview

    # We aren't using these imports in this file, but we want them to be available
    # to import from this module in others.
    # Additionally, python2 doesn't have this, so we need to disable import-error
    # as well.

    # unused-import<W0611>, import-error<E0401> Disabled: Due to backward compatibility between py2 and py3
    from builtins import int, range  # pylint: disable=unused-import,import-error
    from collections import OrderedDict  # pylint: disable=W0611
    from queue import Queue, Empty  # pylint: disable=W0611,import-error

    # unused-import<W0611> Disabled: python2.7 doesn't have subprocess.DEVNULL
    # so this import is only used by python3.
    import subprocess   # pylint: disable=unused-import

elif sys.version_info[0] == 2:
    import httplib as httpclient  # pylint: disable=E0401,W0611
    from urlparse import urlparse  # pylint: disable=E0401
    from Queue import Queue, Empty  # pylint: disable=W0611,import-error

    
    # We want to suppress the following:
    #   -   undefined-variable<E0602>: 
    #           These builtins are not defined in python3
    #   -   redefined-builtin<W0622>:
    #           This is intentional, so that code that wants to use builtins we're
    #           assigning new names to doesn't need to check python versions before
    #           doing so.

    # pylint: disable=undefined-variable,redefined-builtin

    ustr = unicode # Rename Python2 unicode to ustr 
    bytebuffer = buffer
    range = xrange
    int = long


    if sys.version_info[1] >= 7:
        from collections import OrderedDict  # For Py 2.7+
    else:
        from ordereddict import OrderedDict  # Works only on 2.6  # pylint: disable=E0401
else:
    raise ImportError("Unknown python version: {0}".format(sys.version_info))


def get_linux_distribution(get_full_name, supported_dists):
    """Abstract platform.linux_distribution() call which is deprecated as of
       Python 3.5 and removed in Python 3.7"""
    try:
        supported = platform._supported_dists + (supported_dists,)
        osinfo = list(
            platform.linux_distribution(  # pylint: disable=W1505
                full_distribution_name=get_full_name,
                supported_dists=supported
            )
        )

        # The platform.linux_distribution() lib has issue with detecting OpenWRT linux distribution.
        # Merge the following patch provided by OpenWRT as a temporary fix.
        if os.path.exists("/etc/openwrt_release"):
            osinfo = get_openwrt_platform()

        if not osinfo or osinfo == ['', '', '']:
            return get_linux_distribution_from_distro(get_full_name)
        full_name = platform.linux_distribution()[0].strip()  # pylint: disable=W1505
        osinfo.append(full_name)
    except AttributeError:
        return get_linux_distribution_from_distro(get_full_name)

    return osinfo


def get_linux_distribution_from_distro(get_full_name):
    """Get the distribution information from the distro Python module."""
    # If we get here we have to have the distro module, thus we do
    # not wrap the call in a try-except block as it would mask the problem
    # and result in a broken agent installation
    osinfo = list(
        distro.linux_distribution(
            full_distribution_name=get_full_name
        )
    )
    full_name = distro.linux_distribution()[0].strip()
    osinfo.append(full_name)
    return osinfo


def get_openwrt_platform():
    """
    Add this workaround for detecting OpenWRT products because
    the version and product information is contained in the /etc/openwrt_release file.
    """
    result = [None, None, None]
    openwrt_version = re.compile(r"^DISTRIB_RELEASE=['\"](\d+\.\d+.\d+)['\"]")
    openwrt_product = re.compile(r"^DISTRIB_ID=['\"]([\w-]+)['\"]")

    with open('/etc/openwrt_release', 'r') as fh:
        content = fh.readlines()
        for line in content:
            version_matches = openwrt_version.match(line)
            product_matches = openwrt_product.match(line)
            if version_matches:
                result[1] = version_matches.group(1)
            elif product_matches:
                if product_matches.group(1) == "OpenWrt":
                    result[0] = "openwrt"
    return result

def is_file_not_found_error(exception):
    
    # pylint for python2 complains, but FileNotFoundError is
    # defined for python3.
    
    # pylint: disable=undefined-variable

    if sys.version_info[0] == 2:
        # Python 2 uses OSError(errno=2)
        return isinstance(exception, OSError) and exception.errno == 2
    elif sys.version_info[0] == 3:
        return isinstance(exception, FileNotFoundError)
    
    return isinstance(exception, FileNotFoundError)

@contextlib.contextmanager
def subprocess_dev_null():

    if sys.version_info[0] == 3:
        # Suppress no-member errors on python2.7
        yield subprocess.DEVNULL # pylint: disable=no-member
    else:
        try:
            devnull = open(os.devnull, "a+")
            yield devnull
        except Exception:
            yield None
        finally:
            if devnull is not None:
                devnull.close()

def array_to_bytes(buff):
    # Python 3.9 removed the tostring() method on arrays, the new alias is tobytes()
    if sys.version_info[0] == 2:
        return buff.tostring()

    if sys.version_info[0] == 3 and sys.version_info[1] <= 8:
        return buff.tostring()

    return buff.tobytes()
