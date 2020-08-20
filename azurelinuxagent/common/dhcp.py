# Copyright 2018 Microsoft Corporation
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

import os
import socket
import array
import time
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.utils.textutil import hex_dump, hex_dump2, \
    hex_dump3, \
    compare_bytes, str_to_ord, \
    unpack_big_endian, \
    int_to_ip4_addr
from azurelinuxagent.common.exception import DhcpError
from azurelinuxagent.common.osutil import get_osutil


# the kernel routing table representation of 168.63.129.16
KNOWN_WIRESERVER_IP_ENTRY = '10813FA8'
from azurelinuxagent.common.utils.restutil import KNOWN_WIRESERVER_IP # pylint: disable=C0413


def get_dhcp_handler():
    return DhcpHandler()


class DhcpHandler(object):
    """
    Azure use DHCP option 245 to pass endpoint ip to VMs.
    """

    def __init__(self):
        self.osutil = get_osutil()
        self.endpoint = None
        self.gateway = None
        self.routes = None
        self._request_broadcast = False
        self.skip_cache = False

    def run(self):
        """
        Send dhcp request
        Configure default gateway and routes
        Save wire server endpoint if found
        """
        if self.wireserver_route_exists or self.dhcp_cache_exists:
            return

        self.send_dhcp_req()
        self.conf_routes()

    def wait_for_network(self):
        """
        Wait for network stack to be initialized.
        """
        ipv4 = self.osutil.get_ip4_addr()
        while ipv4 == '' or ipv4 == '0.0.0.0': # pylint: disable=R1714
            logger.info("Waiting for network.")
            time.sleep(10)
            logger.info("Try to start network interface.")
            self.osutil.start_network()
            ipv4 = self.osutil.get_ip4_addr()

    @property
    def wireserver_route_exists(self):
        """
        Determine whether a route to the known wireserver
        ip already exists, and if so use that as the endpoint.
        This is true when running in a virtual network.
        :return: True if a route to KNOWN_WIRESERVER_IP exists.
        """
        route_exists = False
        logger.info("Test for route to {0}".format(KNOWN_WIRESERVER_IP))
        try:
            route_table = self.osutil.read_route_table()
            if any([(KNOWN_WIRESERVER_IP_ENTRY in route) for route in route_table]):
                # reset self.gateway and self.routes
                # we do not need to alter the routing table
                self.endpoint = KNOWN_WIRESERVER_IP
                self.gateway = None
                self.routes = None
                route_exists = True
                logger.info("Route to {0} exists".format(KNOWN_WIRESERVER_IP))
            else:
                logger.warn("No route exists to {0}".format(KNOWN_WIRESERVER_IP))
        except Exception as e: # pylint: disable=C0103
            logger.error(
                "Could not determine whether route exists to {0}: {1}".format(
                    KNOWN_WIRESERVER_IP, e))
                    
        return route_exists

    @property
    def dhcp_cache_exists(self):
        """
        Check whether the dhcp options cache exists and contains the
        wireserver endpoint, unless skip_cache is True.
        :return: True if the cached endpoint was found in the dhcp lease
        """
        if self.skip_cache:
            return False

        exists = False

        logger.info("Checking for dhcp lease cache")
        cached_endpoint = self.osutil.get_dhcp_lease_endpoint() # pylint: disable=E1128
        if cached_endpoint is not None:
            self.endpoint = cached_endpoint
            exists = True
        logger.info("Cache exists [{0}]".format(exists))
        return exists

    def conf_routes(self):
        logger.info("Configure routes")
        logger.info("Gateway:{0}", self.gateway)
        logger.info("Routes:{0}", self.routes)
        # Add default gateway
        if self.gateway is not None and self.osutil.is_missing_default_route():
            self.osutil.route_add(0, 0, self.gateway)
        if self.routes is not None:
            for route in self.routes:
                self.osutil.route_add(route[0], route[1], route[2])

    def _send_dhcp_req(self, request):
        __waiting_duration__ = [0, 10, 30, 60, 60]
        for duration in __waiting_duration__:
            try:
                self.osutil.allow_dhcp_broadcast()
                response = socket_send(request)
                validate_dhcp_resp(request, response)
                return response
            except DhcpError as e: # pylint: disable=C0103
                logger.warn("Failed to send DHCP request: {0}", e)
            time.sleep(duration)
        return None

    def send_dhcp_req(self):
        """
        Check if DHCP is available
        """
        dhcp_available =  self.osutil.is_dhcp_available()
        if not dhcp_available:
            logger.info("send_dhcp_req: DHCP not available")
            self.endpoint = KNOWN_WIRESERVER_IP
            return

        # pylint: disable=W0105
        """
        Build dhcp request with mac addr
        Configure route to allow dhcp traffic
        Stop dhcp service if necessary
        """ 
        # pylint: enable=W0105
        
        logger.info("Send dhcp request")
        mac_addr = self.osutil.get_mac_addr()

        # Do unicast first, then fallback to broadcast if fails.
        req = build_dhcp_request(mac_addr, self._request_broadcast)
        if not self._request_broadcast:
            self._request_broadcast = True

        # Temporary allow broadcast for dhcp. Remove the route when done.
        missing_default_route = self.osutil.is_missing_default_route()
        ifname = self.osutil.get_if_name()
        if missing_default_route:
            self.osutil.set_route_for_dhcp_broadcast(ifname)

        # In some distros, dhcp service needs to be shutdown before agent probe
        # endpoint through dhcp.
        if self.osutil.is_dhcp_enabled():
            self.osutil.stop_dhcp_service()

        resp = self._send_dhcp_req(req)

        if self.osutil.is_dhcp_enabled():
            self.osutil.start_dhcp_service()

        if missing_default_route:
            self.osutil.remove_route_for_dhcp_broadcast(ifname)

        if resp is None:
            raise DhcpError("Failed to receive dhcp response.")
        self.endpoint, self.gateway, self.routes = parse_dhcp_resp(resp)


def validate_dhcp_resp(request, response): # pylint: disable=R1710
    bytes_recv = len(response)
    if bytes_recv < 0xF6:
        logger.error("HandleDhcpResponse: Too few bytes received:{0}",
                     bytes_recv)
        return False

    logger.verbose("BytesReceived:{0}", hex(bytes_recv))
    logger.verbose("DHCP response:{0}", hex_dump(response, bytes_recv))

    # check transactionId, cookie, MAC address cookie should never mismatch
    # transactionId and MAC address may mismatch if we see a response
    # meant from another machine
    if not compare_bytes(request, response, 0xEC, 4):
        logger.verbose("Cookie not match:\nsend={0},\nreceive={1}",
                       hex_dump3(request, 0xEC, 4),
                       hex_dump3(response, 0xEC, 4))
        raise DhcpError("Cookie in dhcp respones doesn't match the request")

    if not compare_bytes(request, response, 4, 4):
        logger.verbose("TransactionID not match:\nsend={0},\nreceive={1}",
                       hex_dump3(request, 4, 4),
                       hex_dump3(response, 4, 4))
        raise DhcpError("TransactionID in dhcp respones "
                        "doesn't match the request")

    if not compare_bytes(request, response, 0x1C, 6):
        logger.verbose("Mac Address not match:\nsend={0},\nreceive={1}",
                       hex_dump3(request, 0x1C, 6),
                       hex_dump3(response, 0x1C, 6))
        raise DhcpError("Mac Addr in dhcp respones "
                        "doesn't match the request")


def parse_route(response, option, i, length, bytes_recv): # pylint: disable=W0613
    # http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
    logger.verbose("Routes at offset: {0} with length:{1}", hex(i),
                   hex(length))
    routes = []
    if length < 5:
        logger.error("Data too small for option:{0}", option)
    j = i + 2
    while j < (i + length + 2):
        mask_len_bits = str_to_ord(response[j])
        mask_len_bytes = (((mask_len_bits + 7) & ~7) >> 3)
        mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - mask_len_bits))
        j += 1
        net = unpack_big_endian(response, j, mask_len_bytes)
        net <<= (32 - mask_len_bytes * 8)
        net &= mask
        j += mask_len_bytes
        gateway = unpack_big_endian(response, j, 4)
        j += 4
        routes.append((net, mask, gateway))
    if j != (i + length + 2):
        logger.error("Unable to parse routes")
    return routes


def parse_ip_addr(response, option, i, length, bytes_recv):
    if i + 5 < bytes_recv: # pylint: disable=R1705
        if length != 4:
            logger.error("Endpoint or Default Gateway not 4 bytes")
            return None
        addr = unpack_big_endian(response, i + 2, 4)
        ip_addr = int_to_ip4_addr(addr)
        return ip_addr
    else:
        logger.error("Data too small for option:{0}", option)
    return None


def parse_dhcp_resp(response):
    """
    Parse DHCP response:
    Returns endpoint server or None on error.
    """
    logger.verbose("parse Dhcp Response")
    bytes_recv = len(response)
    endpoint = None
    gateway = None
    routes = None

    # Walk all the returned options, parsing out what we need, ignoring the
    # others. We need the custom option 245 to find the the endpoint we talk to
    # as well as to handle some Linux DHCP client incompatibilities;
    # options 3 for default gateway and 249 for routes; 255 is end.

    i = 0xF0  # offset to first option
    while i < bytes_recv:
        option = str_to_ord(response[i])
        length = 0
        if (i + 1) < bytes_recv:
            length = str_to_ord(response[i + 1])
        logger.verbose("DHCP option {0} at offset:{1} with length:{2}",
                       hex(option), hex(i), hex(length))
        if option == 255: # pylint: disable=R1723
            logger.verbose("DHCP packet ended at offset:{0}", hex(i))
            break
        elif option == 249:
            routes = parse_route(response, option, i, length, bytes_recv)
        elif option == 3:
            gateway = parse_ip_addr(response, option, i, length, bytes_recv)
            logger.verbose("Default gateway:{0}, at {1}", gateway, hex(i))
        elif option == 245:
            endpoint = parse_ip_addr(response, option, i, length, bytes_recv)
            logger.verbose("Azure wire protocol endpoint:{0}, at {1}",
                           endpoint,
                           hex(i))
        else:
            logger.verbose("Skipping DHCP option:{0} at {1} with length {2}",
                           hex(option), hex(i), hex(length))
        i += length + 2
    return endpoint, gateway, routes


def socket_send(request):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 68))
        sock.sendto(request, ("<broadcast>", 67))
        sock.settimeout(10)
        logger.verbose("Send DHCP request: Setting socket.timeout=10, "
                       "entering recv")
        response = sock.recv(1024)
        return response
    except IOError as e: # pylint: disable=C0103
        raise DhcpError("{0}".format(e))
    finally:
        if sock is not None:
            sock.close()


def build_dhcp_request(mac_addr, request_broadcast):
    """
    Build DHCP request string.
    """
    #
    # typedef struct _DHCP {
    #  UINT8   Opcode;                    /* op:    BOOTREQUEST or BOOTREPLY */
    #  UINT8   HardwareAddressType;       /* htype: ethernet */
    #  UINT8   HardwareAddressLength;     /* hlen:  6 (48 bit mac address) */
    #  UINT8   Hops;                      /* hops:  0 */
    #  UINT8   TransactionID[4];          /* xid:   random */
    #  UINT8   Seconds[2];                /* secs:  0 */
    #  UINT8   Flags[2];                  /* flags: 0 or 0x8000 for broadcast*/
    #  UINT8   ClientIpAddress[4];        /* ciaddr: 0 */
    #  UINT8   YourIpAddress[4];          /* yiaddr: 0 */
    #  UINT8   ServerIpAddress[4];        /* siaddr: 0 */
    #  UINT8   RelayAgentIpAddress[4];    /* giaddr: 0 */
    #  UINT8   ClientHardwareAddress[16]; /* chaddr: 6 byte eth MAC address */
    #  UINT8   ServerName[64];            /* sname:  0 */
    #  UINT8   BootFileName[128];         /* file:   0  */
    #  UINT8   MagicCookie[4];            /*   99  130   83   99 */
    #                                        /* 0x63 0x82 0x53 0x63 */
    #     /* options -- hard code ours */
    #
    #     UINT8 MessageTypeCode;              /* 53 */
    #     UINT8 MessageTypeLength;            /* 1 */
    #     UINT8 MessageType;                  /* 1 for DISCOVER */
    #     UINT8 End;                          /* 255 */
    # } DHCP;
    #

    # tuple of 244 zeros
    # (struct.pack_into would be good here, but requires Python 2.5)
    request = [0] * 244

    trans_id = gen_trans_id()

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3): # pylint: disable=C0103
        request[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4): # pylint: disable=C0103
        request[4 + a] = str_to_ord(trans_id[a])

    logger.verbose("BuildDhcpRequest: transactionId:%s,%04X" % (
        hex_dump2(trans_id),
        unpack_big_endian(request, 4, 4)))

    if request_broadcast:
        # set broadcast flag to true to request the dhcp server
        # to respond to a boradcast address,
        # this is useful when user dhclient fails.
        request[0x0A] = 0x80; # pylint: disable=W0301

    # fill in ClientHardwareAddress
    for a in range(0, 6): # pylint: disable=C0103
        request[0x1C + a] = str_to_ord(mac_addr[a])

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8): # pylint: disable=C0103
        request[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("B", request)


def gen_trans_id():
    return os.urandom(4)
