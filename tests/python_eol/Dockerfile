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
FROM ubuntu:16.04
ARG PYTHON_VERSION
LABEL description="Test environment for WALinuxAgent"

SHELL ["/bin/bash", "-c"]

RUN \
    apt-get update && \
    apt-get -y install curl bzip2 sudo && \
    groupadd waagent && \
    useradd --shell /bin/bash --create-home -g waagent waagent && \
    curl -sSf --retry 5 -o /tmp/python-${PYTHON_VERSION}.tar.bz2 https://dcrdata.blob.core.windows.net/python/python-${PYTHON_VERSION}.tar.bz2 && \
    tar xjf /tmp/python-${PYTHON_VERSION}.tar.bz2 --directory / && \
    rm -f /tmp/python-${PYTHON_VERSION}.tar.bz2 && \
    echo $'\
        \n\
        cd /home/waagent \n\
        source /home/waagent/virtualenv/python'${PYTHON_VERSION}/bin/activate$' \n\
        function run-tests { \n\
            nosetests --verbose --ignore-files test_cgroupconfigurator_sudo.py /home/waagent/WALinuxAgent/tests \n\
        } \n\
        function run-sudo-tests { \n\
            nosetests --verbose /home/waagent/WALinuxAgent/tests/ga/test_cgroupconfigurator_sudo.py \n\
        } \n\
        ' | tee -a /home/waagent/.profile >> ~/.profile && \
    sed -i 's/mesg n || true/tty -s \&\& mesg n/' ~/.profile && \
    :

#
# TODO: Some unit tests create helper scripts that use 'python3' as shebang; we should probably port them to Bash, but installing Python 3 as a workaround for now.
#
RUN \
    if [[ "${PYTHON_VERSION}" == "2.6" ]]; then \
      apt-get -y install python3; \
    fi

USER waagent:waagent



