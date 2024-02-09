#
# * Sample command to build the image:
#
#   docker build -t waagenttests .
#
# * Sample command to execute a container interactively:
#
#   docker run --rm -it -v /home/nam/src/WALinuxAgent:/home/waagent/WALinuxAgent waagenttests bash --login
#
FROM mcr.microsoft.com/cbl-mariner/base/core:2.0
LABEL description="Test environment for WALinuxAgent"

SHELL ["/bin/bash", "-c"]

#
# Install the required packages as root
#
USER root

RUN \
    tdnf -y update                                                                                            && \
    # mariner packages can be found in this repository https://cvedashboard.azurewebsites.net/#/packages         \
    #                                                                                                            \
    # Install basic dependencies                                                                                 \
    #                                                                                                            \
    tdnf -y install git python3 python3-devel wget bzip2 ca-certificates                                      && \
                                                                                                                 \
    #                                                                                                            \
    # Install LISA dependencies                                                                                  \
    #                                                                                                            \
    tdnf install -y git gcc gobject-introspection-devel cairo-devel pkg-config python3-devel libvirt-devel       \
            cairo-gobject binutils kernel-headers glibc-devel python3-pip python3-virtualenv                  && \
                                                                                                                 \
    #                                                                                                            \
    # Install test dependencies                                                                                  \
    #                                                                                                            \
    tdnf -y install zip tar                                                                                   && \
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
    tdnf -y install azure-cli                                                                                 && \
    tdnf clean all                                                                                            && \
    :

#
# Install LISA as user waagent
#
USER waagent

RUN \
    export PATH="$HOME/.local/bin:$PATH"                                                                      && \
                                                                                                                 \
    #                                                                                                            \
    # Install LISA.                                                                                              \
    #                                                                                                            \
    # (note that we use a specific commit, which is the version of LISA that has been verified to work with our  \
    # tests; when taking a new LISA version, make sure to verify that the tests work OK before pushing the       \
    # Docker image to our registry)                                                                              \
    #                                                                                                            \
    cd $HOME                                                                                                  && \
    git clone https://github.com/microsoft/lisa.git                                                           && \
    cd lisa                                                                                                   && \
    git checkout 2c16e32001fdefb9572dff61241451b648259dbf                                                     && \
                                                                                                                 \
    python3 -m pip install --upgrade pip                                                                      && \
    python3 -m pip install --editable .[azure,libvirt] --config-settings editable_mode=compat                 && \
                                                                                                                 \
    #                                                                                                            \
    # Install additional test dependencies                                                                       \
    #                                                                                                            \
    # (note that we update azure-mgmt-compute to 29.1.0 - LISA installs 26.1; this is needed in order to access  \
    # osProfile.linuxConfiguration.enableVMAgentPlatformUpdates in the VM model - that property is used by some  \
    # tests, such as Agent versioning)                                                                           \
    #                                                                                                            \
    python3 -m pip install distro msrestazure pytz                                                            && \
    python3 -m pip install azure-mgmt-compute==29.1.0 --upgrade                                               && \
                                                                                                                 \
    #                                                                                                            \
    # Download Pypy to a known location, from which it will be installed to the test VMs.                        \
    #                                                                                                            \
    wget https://dcrdata.blob.core.windows.net/python/pypy3.7-x64.tar.bz2 -O /tmp/pypy3.7-x64.tar.bz2         && \
    wget https://dcrdata.blob.core.windows.net/python/pypy3.7-arm64.tar.bz2 -O /tmp/pypy3.7-arm64.tar.bz2     && \
                                                                                                                 \
    #                                                                                                            \
    # Install pudb, which can be useful to debug issues in the image                                             \
    #                                                                                                            \
    python3 -m pip install pudb                                                                               && \
                                                                                                                 \
    #                                                                                                            \
    # The setup for the tests depends on a few paths; add those to the profile                                   \
    #                                                                                                            \
    echo 'export PYTHONPATH="$HOME/WALinuxAgent"' >> $HOME/.bash_profile                                      && \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> $HOME/.bash_profile                                        && \
    echo 'cd $HOME' >> $HOME/.bash_profile                                                                    && \
    :

