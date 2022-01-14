#!/bin/bash

# Helper file which tries to access Wireserver on system reboot. Also prints out iptable rules if non-root and still
# able to access Wireserver

# Args:            0                 1
# Usage ./access_wire_ip.sh <Path-to-iptables>

USER=$(whoami)
echo "$(date --utc +%FT%T.%3NZ): Running as user: $USER"

function check_online
{
    ping 8.8.8.8 -c 1 -i .2 -t 30 > /dev/null 2>&1 && echo 0 || echo 1
}

# Check more, sleep less
MAX_CHECKS=10
# Initial starting value for checks
CHECKS=0
IS_ONLINE=$(check_online)

# Loop while we're not online.
while [ "$IS_ONLINE" -eq 1 ]; do

    CHECKS=$((CHECKS + 1))
    if [ $CHECKS -gt $MAX_CHECKS ]; then
        break
    fi

    echo "$(date --utc +%FT%T.%3NZ): Network still not accessible"
    # We're offline. Sleep for a bit, then check again
    sleep 1;
    IS_ONLINE=$(check_online)

done

if [ "$IS_ONLINE" -eq 1 ]; then
    # We will never be able to get online. Kill script.
    echo "Unable to connect to network, exiting now"
    echo "ExitCode: 1"
    exit 1
fi

echo "Finally online, Time: $(date --utc +%FT%T.%3NZ)"
echo "Trying to contact Wireserver as $USER to see if accessible"

echo ""
echo "IPTables before accessing Wireserver"
sudo "$1" -t security -L -nxv
echo ""

file_name="/var/tmp/wire-versions-root.xml"
if [[ "$USER" != "root" ]]; then
  file_name="/var/tmp/wire-versions-non-root.xml"
fi

WIRE_IP=$(cat /var/lib/waagent/WireServerEndpoint 2>/dev/null || echo '168.63.129.16' | tr -d '[:space:]')
wget --tries=3 "http://$WIRE_IP/?comp=versions" --timeout=5 -O "$file_name"
WIRE_EC=$?
echo "ExitCode: $WIRE_EC"

if [[ "$USER" != "root" && "$WIRE_EC" == 0  ]]; then
  echo "Wireserver should not be accessible for non-root user ($USER), IPTable rules -"
  sudo "$1" -t security -L -nxv
fi