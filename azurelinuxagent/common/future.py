import platform
import sys
import os
import re

# Note broken dependency handling to avoid potential backward
# compatibility issues on different distributions
try:
    import distro # pylint: disable=E0401
except Exception:
    pass

# pylint: disable=W0105
"""
Add alias for python2 and python3 libs and functions.
""" 
# pylint: enable=W0105

if sys.version_info[0] == 3:
    import http.client as httpclient # pylint: disable=W0611,import-error
    from urllib.parse import urlparse # pylint: disable=W0611,import-error,no-name-in-module

    """Rename Python3 str to ustr""" # pylint: disable=W0105
    ustr = str # pylint: disable=C0103

    bytebuffer = memoryview # pylint: disable=C0103

    from collections import OrderedDict # pylint: disable=W0611
    from queue import PriorityQueue

elif sys.version_info[0] == 2:
    import httplib as httpclient # pylint: disable=E0401,W0611
    from urlparse import urlparse # pylint: disable=E0401
    from Queue import PriorityQueue

    """Rename Python2 unicode to ustr""" # pylint: disable=W0105
    ustr = unicode # pylint: disable=E0602,invalid-name

    bytebuffer = buffer # pylint: disable=E0602,invalid-name

    if sys.version_info[1] >= 7:
        from collections import OrderedDict  # For Py 2.7+ # pylint: disable=C0412
    else:
        from ordereddict import OrderedDict  # Works only on 2.6 # pylint: disable=E0401
else:
    raise ImportError("Unknown python version: {0}".format(sys.version_info))


def get_linux_distribution(get_full_name, supported_dists):
    """Abstract platform.linux_distribution() call which is deprecated as of
       Python 3.5 and removed in Python 3.7"""
    try:
        supported = platform._supported_dists + (supported_dists,) # pylint: disable=W0212
        osinfo = list(
            platform.linux_distribution( # pylint: disable=W1505
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
        full_name = platform.linux_distribution()[0].strip() # pylint: disable=W1505
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

    with open('/etc/openwrt_release', 'r') as fh: # pylint: disable=C0103
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