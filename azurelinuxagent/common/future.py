import platform
import sys

if float(sys.version[:3]) >= 3.5:
    import distro
    
"""
Add alias for python2 and python3 libs and functions.
"""

if sys.version_info[0] == 3:
    import http.client as httpclient
    from urllib.parse import urlparse

    """Rename Python3 str to ustr"""
    ustr = str

    bytebuffer = memoryview

elif sys.version_info[0] == 2:
    import httplib as httpclient
    from urlparse import urlparse

    """Rename Python2 unicode to ustr"""
    ustr = unicode

    bytebuffer = buffer

else:
    raise ImportError("Unknown python version: {0}".format(sys.version_info))


def get_linux_distribution(get_full_name, supported_dists):
    """Abstract platform.linux_distribution() call which is deprecated as of
       Python 3.5"""
    if float(sys.version[:3]) >= 3.5:
        platform_module = distro
        osinfo = list(distro.linux_distribution(
            full_distribution_name=get_full_name
        ))
    else:
        platform_module = platform
        supported = platform._supported_dists + (supported_dists,)
        osinfo = list(platform.linux_distribution(
            full_distribution_name=get_full_name,
            supported_dists=supported
        ))
    full_name = platform_module.linux_distribution()[0].strip()
    osinfo.append(full_name)

    return osinfo
