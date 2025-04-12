#!/usr/bin/env bash
#
# The pre-built Python virtual environments have hard dependencies on some of the shared libraries in Open SSL 1.0/1.1 (e.g libssl.so.1.0.0), which are not available on current Ubuntu versions.
# Modules like hashlib and ssl will fail to import. The Agent uses classes HTTPSConnection and HTTPS, which depend on the ssl module. Those classes are added conditionally on the
# import of ssl on httplib.py and http/client.py with code similar to:
#
#     try:
#        import ssl
#    except ImportError:
#        pass
#    else:
#        class HTTPSConnection(HTTPConnection):...
#        class HTTPS(HTTP):...
#        def FakeSocket (sock, sslobj):...
#
# Since the import fails, the classes will be undefined. To work around that, we define dummy items that raise NotImplementedError. The unit tests mock those classes anyway, so the
# actual implementation does not really matter.
#
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "Usage: patch_python_venv.sh <python_version(major.minor, e.g. 2.6)>"
  exit 1
fi

PYTHON_VERSION=$1

if [[ "${PYTHON_VERSION}" =~ ^2\.[0-9]$ ]]; then
  # Patch httplib.py on Python 2
  cat >> /opt/python/${PYTHON_VERSION}/lib/python${PYTHON_VERSION}/httplib.py << ...

# Added by WALinuxAgent dev team to work around the lack of OpenSSL 1.0 shared libraries
class HTTPSConnection(HTTPConnection):
    default_port = HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        raise NotImplementedError()

    def connect(self):
        raise NotImplementedError()

__all__.append("HTTPSConnection")

class HTTPS(HTTP):
    _connection_class = HTTPSConnection

    def __init__(self, host='', port=None, key_file=None, cert_file=None, strict=None):
        raise NotImplementedError()

def FakeSocket (sock, sslobj):
    raise NotImplementedError()
...

elif [[ "${PYTHON_VERSION}" =~ ^3\.[0-9]$ ]]; then
  # Patch http/client.py on Python 3
  path='*/lib/python'${PYTHON_VERSION}'/http/client.py'
  cat >> "$(find /opt -wholename $path)" << ...

# Added by WALinuxAgent dev team to work around the lack of OpenSSL 1.0 shared libraries
class HTTPSConnection(HTTPConnection):
    default_port = HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *, context=None, check_hostname=None):
        raise NotImplementedError()

    def connect(self):
        raise NotImplementedError()

__all__.append("HTTPSConnection")
...
fi
