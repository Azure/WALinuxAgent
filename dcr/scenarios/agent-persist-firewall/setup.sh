#!/usr/bin/env bash

#            1          2           3
# Usage:
set -euxo pipefail

d=$(which date)
ipt=$(which iptables)
username="dcr"
script_dir=$(dirname "$0")
cp "$script_dir/access_wire_ip.sh" "/usr/bin/"
chmod 777 "/usr/bin/access_wire_ip.sh"
mkdir -p /home/$username || echo "this is only needed for Suse VMs for running cron jobs as non-root"
# Setup Cron jobs
echo "@reboot ($d --utc +\\%FT\\%T.\\%3NZ && /usr/bin/access_wire_ip.sh $ipt) > /var/tmp/reboot-cron-root.log 2>&1" | crontab -u root -
echo "@reboot ($d --utc +\\%FT\\%T.\\%3NZ && /usr/bin/access_wire_ip.sh $ipt) > /var/tmp/reboot-cron-non-root.log 2>&1" | crontab -u $username -
(crontab -l 2>/dev/null; echo "@reboot ($d --utc +\%FT\%T.\%3NZ) > /var/log/reboot_time.txt 2>&1") | crontab -u root -
s=$(which systemctl)
(crontab -l 2>/dev/null; echo "@reboot ($s status walinuxagent-network-setup.service || $s status waagent-network-setup.service) > /var/log/reboot_network_setup.txt 2>&1)") | crontab -u root -

# Enable Firewall for all distros
sed -i 's/OS.EnableFirewall=n/OS.EnableFirewall=y/g' /etc/waagent.conf

# Restart agent to pick up the new conf
systemctl restart waagent || systemctl restart walinuxagent

# Ensure that the setup file exists
file="wa*-network-setup.service"
[ "$(ls /usr/lib/systemd/system/$file /lib/systemd/system/$file 2>/dev/null | wc -w)" -gt 0 ] && echo "agent-network-setup file exists" || echo "agent-network-setup file does not exists"