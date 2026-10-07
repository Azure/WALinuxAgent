# Compose Content for: L2-platform/runtime-compatibility-helpers.md

Total files: 1

---

## setup.py

### Structural symbols

- `ustr`
- `bytebuffer`
- `range`
- `int`
- `UTC`
- `_UTC`
- `_UTC.utcoffset`
- `_UTC.utcoffset.self`
- `_UTC.utcoffset.dt`
- `_UTC.tzname`
- `_UTC.tzname.self`
- `_UTC.tzname.dt`
- `_UTC.dst`
- `_UTC.dst.self`
- `_UTC.dst.dt`
- `%REPO%/azurelinuxagent/common/future.py.datetime_max_utc`
- `%REPO%/azurelinuxagent/common/future.py.datetime_min_utc`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution.get_full_name`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution.supported_dists`
- `%REPO%/azurelinuxagent/common/future.py.get_openwrt_platform`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution_from_distro`
- `%REPO%/azurelinuxagent/common/future.py.get_linux_distribution_from_distro.get_full_name`
- `%REPO%/azurelinuxagent/common/future.py.is_file_not_found_error`
- `%REPO%/azurelinuxagent/common/future.py.is_file_not_found_error.exception`
- `%REPO%/azurelinuxagent/common/future.py.subprocess_dev_null`
- `%REPO%/azurelinuxagent/common/future.py.array_to_bytes`
- `%REPO%/azurelinuxagent/common/future.py.array_to_bytes.buff`

### Source excerpt

````
import contextlib
import datetime
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


````

---
