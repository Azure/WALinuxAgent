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
    apt-get install -y git python3.10 python3.10-dev curl                                                     && \
    ln /usr/bin/python3.10 /usr/bin/python3                                                                   && \
                                                                                                                 \
    #                                                                                                            \
    # Install LISA dependencies                                                                                  \
    #                                                                                                            \
    apt-get install -y git gcc libgirepository1.0-dev libcairo2-dev qemu-utils libvirt-dev                       \
            python3-pip python3-venv                                                                          && \
    #                                                                                                            \
    # Create user waagent, which is used to execute the tests                                                    \
    #                                                                                                            \
    groupadd waagent                                                                                          && \
    useradd --shell /bin/bash --create-home -g waagent waagent                                                && \
    :

#
# Do the Poetry and LISA setup as waagent
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
                                                                                                                 \
    python3 -m pip install --upgrade pip                                                                      && \
    python3 -m pip install --editable .[azure,libvirt] --config-settings editable_mode=compat                 && \
                                                                                                                 \
    #                                                                                                            \
    # Install additional test dependencies                                                                       \
    #                                                                                                            \
    python3 -m pip install distro msrestazure                                                                 && \
                                                                                                                 \
    #                                                                                                            \
    # The setup for the tests depends on a couple of paths; add those to the profile                             \
    #                                                                                                            \
    echo 'export PYTHONPATH="$HOME/WALinuxAgent"' >> $HOME/.bash_profile                                      && \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> $HOME/.bash_profile                                        && \
    :

