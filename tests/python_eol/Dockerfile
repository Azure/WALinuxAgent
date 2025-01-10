#
# Environment to execute the WALinuxAgent unit tests for some versions of Python that have reached EOL and are no longer available
# in the official repositories.
#
# To build the image, set the PYTHON_VERSION argument to 2.6 or 3.4:
#
#    * docker build -t python2.6 --build-arg PYTHON_VERSION=2.6 .
#    * docker build -t python3.4 --build-arg PYTHON_VERSION=3.4 .
#
# We add a couple of convenience functions to execute the unit tests to the profiles of waagent and root; these can be useful in interactive sessions. Note
# that these functions assume the root of the source code has been mounted at /home/waagent/WALinuxAgent.
#
# Also, we precede "mesg n" with "tty -s" in root's profile to avoid the "standard input is not a tty" message when not running the container interactively.
#
# Sample commands:
#
#    * Start an interactive session: docker run --rm -it -v WALinuxAgent:/home/waagent/WALinuxAgent python2.6 bash --login
#    * Run unit tests:               docker run --rm -v WALinuxAgent:/home/waagent/WALinuxAgent python2.6 bash --login -c run-tests
#    * Run tests that require root:  docker run --user root --rm -v WALinuxAgent:/home/waagent/WALinuxAgent python2.6 bash --login -c run-sudo-tests
#
FROM mcr.microsoft.com/mirror/docker/library/ubuntu:24.04
ARG PYTHON_VERSION
LABEL description="Test environment for WALinuxAgent"

SHELL ["/bin/bash", "-c"]

RUN <<..
    #
    # Install the Python venv
    #
    apt-get update
    apt-get -y install curl bzip2 sudo
    groupadd waagent
    useradd --shell /bin/bash --create-home -g waagent waagent
    curl -sSf --retry 5 -o /tmp/python-${PYTHON_VERSION}.tar.bz2 https://dcrdata.blob.core.windows.net/python/python-${PYTHON_VERSION}.tar.bz2
    tar xjf /tmp/python-${PYTHON_VERSION}.tar.bz2 --directory /
    chown -R waagent:waagent /home/waagent  # The UID:GID in the tarball may not match those of the user, so we need to fix that.
    rm -f /tmp/python-${PYTHON_VERSION}.tar.bz2

    #
    # Add the convenience functions to the profiles of waagent and root
    #
    (cat << ...
cd /home/waagent
source /home/waagent/virtualenv/python${PYTHON_VERSION}/bin/activate
function run-tests {
    nosetests --verbose --ignore-files test_cgroupconfigurator_sudo.py /home/waagent/WALinuxAgent/tests
}
function run-sudo-tests {
    nosetests --verbose /home/waagent/WALinuxAgent/tests/ga/test_cgroupconfigurator_sudo.py
}
...
    ) | tee -a /home/waagent/.profile >> ~/.profile
    sed -i 's/mesg n || true/tty -s \&\& mesg n/' ~/.profile

    #
    # TODO: Some unit tests create helper scripts that use 'python3' as shebang; we should probably port them to Bash, but installing Python 3 as a workaround for now.
    #
    if [[ "${PYTHON_VERSION}" == "2.6" ]]; then
        apt-get -y install python3
    fi
    #
    # The python 2.6 and 3.4 virtual environments have hard dependencies on some of the shared libraries in Open SSL 1.0 (e.g libssl.so.1.0.0), which is not available beyond Ubuntu 16.
    # Modules like hashlib and ssl will fail to import on more recent versions of Ubuntu. The Agent uses classes HTTPSConnection and HTTPS, which depend on the ssl module. Those classes
    # are added conditionally on the import of ssl on httplib.py and http/client.py with code similar to:
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
    if [[ "${PYTHON_VERSION}" == "2.6" ]]; then
        cat >> /opt/python/2.6.9/lib/python2.6/httplib.py << ...
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

    elif [[ "${PYTHON_VERSION}" == "3.4" ]]; then
        cat >> /opt/python/3.4.8/lib/python3.4/http/client.py << ...
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
..

USER waagent:waagent



