# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

MANIFEST_NORMAL = """echo,### Probing Directories ###
ll,/var/log
ll,$LIB_DIR

echo,### Gathering Configuration Files ###
copy,/etc/*-release
copy,/etc/HOSTNAME
copy,/etc/hostname
copy,/etc/waagent.conf
echo,

echo,### Gathering Log Files ###
copy,$AGENT_LOG*
copy,/var/log/dmesg*
copy,/var/log/syslog*
copy,/var/log/auth*
copy,$LOG_DIR/*/*
copy,$LOG_DIR/*/*/*
copy,$LOG_DIR/custom-script/handler.log
echo,

echo,### Gathering Extension Files ###
copy,$LIB_DIR/*.xml
copy,$LIB_DIR/waagent_status.json
copy,$LIB_DIR/*/status/*.status
copy,$LIB_DIR/*/config/*.settings
copy,$LIB_DIR/*/config/HandlerState
copy,$LIB_DIR/*/config/HandlerStatus
copy,$LIB_DIR/*.agentsManifest
copy,$LIB_DIR/error.json
copy,$LIB_DIR/Incarnation
copy,$LIB_DIR/history/*.zip
echo,
"""

MANIFEST_FULL = """echo,### Probing Directories ###
ll,/var/log
ll,$LIB_DIR
ll,/etc/udev/rules.d

echo,### Gathering Configuration Files ###
copy,$LIB_DIR/provisioned
copy,/etc/fstab
copy,/etc/ssh/sshd_config
copy,/boot/grub*/grub.c*
copy,/boot/grub*/menu.lst
copy,/etc/*-release
copy,/etc/HOSTNAME
copy,/etc/hostname
copy,/etc/network/interfaces
copy,/etc/network/interfaces.d/*.cfg
copy,/etc/netplan/50-cloud-init.yaml
copy,/etc/nsswitch.conf
copy,/etc/resolv.conf
copy,/run/systemd/resolve/stub-resolv.conf
copy,/run/resolvconf/resolv.conf
copy,/etc/sysconfig/iptables
copy,/etc/sysconfig/network
copy,/etc/sysconfig/network/ifcfg-eth*
copy,/etc/sysconfig/network/routes
copy,/etc/sysconfig/network-scripts/ifcfg-eth*
copy,/etc/sysconfig/network-scripts/route-eth*
copy,/etc/sysconfig/SuSEfirewall2
copy,/etc/ufw/ufw.conf
copy,/etc/waagent.conf
copy,/var/lib/dhcp/dhclient.eth0.leases
copy,/var/lib/dhclient/dhclient-eth0.leases
copy,/var/lib/wicked/lease-eth0-dhcp-ipv4.xml
echo,

echo,### Gathering Log Files ###
copy,$AGENT_LOG*
copy,/var/log/syslog*
copy,/var/log/rsyslog*
copy,/var/log/messages*
copy,/var/log/kern*
copy,/var/log/dmesg*
copy,/var/log/dpkg*
copy,/var/log/yum*
copy,/var/log/cloud-init*
copy,/var/log/boot*
copy,/var/log/auth*
copy,/var/log/secure*
copy,$LOG_DIR/*/*
copy,$LOG_DIR/*/*/*
copy,$LOG_DIR/custom-script/handler.log
copy,$LOG_DIR/run-command/handler.log
echo,

echo,### Gathering Extension Files ###
copy,$LIB_DIR/ExtensionsConfig.*.xml
copy,$LIB_DIR/*/status/*.status
copy,$LIB_DIR/*/config/*.settings
copy,$LIB_DIR/*/config/HandlerState
copy,$LIB_DIR/*/config/HandlerStatus
copy,$LIB_DIR/GoalState.*.xml
copy,$LIB_DIR/HostingEnvironmentConfig.xml
copy,$LIB_DIR/*.manifest.xml
copy,$LIB_DIR/SharedConfig.xml
copy,$LIB_DIR/ManagedIdentity-*.json
copy,$LIB_DIR/error.json
copy,$LIB_DIR/Incarnation
copy,$LIB_DIR/waagent_status.json
copy,$LIB_DIR/history/*.zip
echo,

echo,### Gathering Disk Info ###
diskinfo,
"""