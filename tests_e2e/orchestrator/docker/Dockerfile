#
# * Sample command to build the image:
#
#   docker build -t waagenttests .
#
# * Sample command to execute a container interactively:
#
#   docker run --rm -it -v /home/nam/src/WALinuxAgent:/home/waagent/WALinuxAgent waagenttests bash --login
#
FROM ubuntu:latest
LABEL description="Test environment for WALinuxAgent"

SHELL ["/bin/bash", "-c"]

#
# Install the required packages as root
#
USER root

RUN \
    apt-get update                                                                                            && \
                                                                                                                 \
    #                                                                                                            \
    # Install basic dependencies                                                                                 \
    #                                                                                                            \
    apt-get install -y git python3.10 python3.10-dev wget bzip2                                               && \
    ln /usr/bin/python3.10 /usr/bin/python3                                                                   && \
                                                                                                                 \
    #                                                                                                            \
    # Install LISA dependencies                                                                                  \
    #                                                                                                            \
    apt-get install -y git gcc libgirepository1.0-dev libcairo2-dev qemu-utils libvirt-dev                       \
            python3-pip python3-venv                                                                          && \
                                                                                                                 \
    #                                                                                                            \
    # Install test dependencies                                                                                  \
    #                                                                                                            \
    apt-get install -y zip                                                                                    && \
                                                                                                                 \
    #                                                                                                            \
    # Create user waagent, which is used to execute the tests                                                    \
    #                                                                                                            \
    groupadd waagent                                                                                          && \
    useradd --shell /bin/bash --create-home -g waagent waagent                                                && \
                                                                                                                 \
    #                                                                                                            \
    # Install the Azure CLI                                                                                      \
    #                                                                                                            \
    apt-get install ca-certificates curl apt-transport-https lsb-release gnupg                                && \
    mkdir -p /etc/apt/keyrings                                                                                && \
    curl -sLS https://packages.microsoft.com/keys/microsoft.asc                                                  \
        | gpg --dearmor                                                                                          \
        | tee /etc/apt/keyrings/microsoft.gpg > /dev/null                                                     && \
    chmod go+r /etc/apt/keyrings/microsoft.gpg                                                                && \
    AZ_REPO=$(lsb_release -cs)                                                                                && \
    echo "deb [arch=`dpkg --print-architecture` signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" \
      | tee /etc/apt/sources.list.d/azure-cli.list                                                            && \
    apt-get update                                                                                            && \
    apt-get install azure-cli                                                                                 && \
    :

#
# Install LISA as user waagent
#
USER waagent

RUN \
    export PATH="$HOME/.local/bin:$PATH"                                                                      && \
                                                                                                                 \
    #                                                                                                            \
    # Install LISA                                                                                               \
    #                                                                                                            \
    cd $HOME                                                                                                  && \
    git clone https://github.com/microsoft/lisa.git                                                           && \
    cd lisa                                                                                                   && \
    git checkout 05aaf490df0ce24018c6ab4e714bcc9ca8765c76                                                     && \
                                                                                                                 \
    python3 -m pip install --upgrade pip                                                                      && \
    python3 -m pip install --editable .[azure,libvirt] --config-settings editable_mode=compat                 && \
                                                                                                                 \
    #                                                                                                            \
    # Install additional test dependencies                                                                       \
    #                                                                                                            \
    python3 -m pip install distro msrestazure pytz                                                            && \
    python3 -m pip install azure-mgmt-compute --upgrade                                                       && \
                                                                                                                 \
    #                                                                                                            \
    # Download Pypy to a known location, from which it will be installed to the test VMs.                        \
    #                                                                                                            \
    wget https://dcrdata.blob.core.windows.net/python/pypy3.7-x64.tar.bz2 -O /tmp/pypy3.7-x64.tar.bz2         && \
    wget https://dcrdata.blob.core.windows.net/python/pypy3.7-arm64.tar.bz2 -O /tmp/pypy3.7-arm64.tar.bz2     && \
                                                                                                                 \
    #                                                                                                            \
    # The setup for the tests depends on a few paths; add those to the profile                                   \
    #                                                                                                            \
    echo 'export PYTHONPATH="$HOME/WALinuxAgent"' >> $HOME/.bash_profile                                      && \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> $HOME/.bash_profile                                        && \
    echo 'cd $HOME' >> $HOME/.bash_profile                                                                    && \
    :

