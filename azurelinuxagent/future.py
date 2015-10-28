import sys

"""
Add alies for python2 and python3 libs and fucntions.
"""

if sys.version_info[0]== 3:
    import http.client as httpclient
    from urllib.parse import urlparse
    text = str
    bytebuffer = memoryview
    read_input = input
elif sys.version_info[0] == 2:
    import httplib as httpclient
    from urlparse import urlparse
    text = unicode
    bytebuffer = buffer
    read_input = raw_input
else:
    raise ImportError("Unknown python version:{0}".format(sys.version_info))

