import sys

"""
Add alies for python2 and python3 libs and fucntions.
"""

if sys.version_info[0]== 3:
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
    raise ImportError("Unknown python version:{0}".format(sys.version_info))

