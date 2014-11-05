# Windows Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
import os
import json
import re
import socket
import array
import time
import walinuxagent.logger as logger
import walinuxagent.utils.restutil as restutil
from walinuxagent.utils.osutil import CurrOS, CurrOSInfo
import walinuxagent.utils.fileutil as fileutil
import walinuxagent.utils.shellutil as shellutil
from walinuxagent.utils.textutil import *

class DhcpHandler():
    def __init__(self):
        self.endpoint = None
        self.gateway = None
        self.routes = None

    def probe(self):
        macAddress = CurrOS.GetMacAddress()
        req = BuildDhcpRequest(macAddress)
        resp = SendDhcpRequest(req)
        endpoint, gateway, routes = ParseDhcpResponse(resp)
        self.endpoint = endpoint
        self.gateway = gateway
        self.routes = routes

    def getEndpoint(self):
        return self.endpoint

    def configNetwork(self):
        pass

def ValidateDhcpResponse(request, response):
    bytesReceived = len(response)
    if bytesReceived < 0xF6:
        logger.Error("HandleDhcpResponse: Too few bytes received:{0}", 
                     str(bytesReceived))
        return False

    logger.Verbose("BytesReceived:{0}", hex(bytesReceived))
    logger.Verbose("DHCP response:{0}", HexDump(response, bytesReceived))

    # check transactionId, cookie, MAC address cookie should never mismatch
    # transactionId and MAC address may mismatch if we see a response 
    # meant from another machine
    if not CompareBytes(request, response, 0xEC, 4):
        logger.Verbose("Cookie not match:\nsend={0},\nreceive={1}", 
                       HexDump3(request, 0xEC, 4),
                       HexDump3(response, 0xEC, 4))
        raise ValueError("Cookie in dhcp respones doesn't match the request")

    if not CompareBytes(request, response, 4, 4):
        logger.Verbose("TransactionID not match:\nsend={0},\nreceive={1}", 
                       HexDump3(request, 4, 4),
                       HexDump3(response, 4, 4))
        raise ValueError("TransactionID in dhcp respones "
                         "doesn't match the request")

    if not CompareBytes(request, response, 0x1C, 6):
        logger.Verbose("Mac Address not match:\nsend={0},\nreceive={1}", 
                       HexDump3(request, 0x1C, 6),
                       HexDump3(response, 0x1C, 6))
        raise ValueError("Mac Addr in dhcp respones doesn't match the request")

def ParseRoute(response, option, i, length, bytesReceived):
    # http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
    logger.Verbose("Routes at offset: {0} with length:{1}", 
                   hex(i), 
                   hex(length))
    routes = []
    if length < 5:
        logger.Error("Data too small for option:{0}", str(option))
    j = i + 2
    while j < (i + length + 2):
        maskLengthBits = Ord(response[j])
        maskLengthBytes = (((maskLengthBits + 7) & ~7) >> 3)
        mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - maskLengthBits))
        j += 1
        net = UnpackBigEndian(response, j, maskLengthBytes)
        net <<= (32 - maskLengthBytes * 8)
        net &= mask
        j += maskLengthBytes
        gateway = UnpackBigEndian(response, j, 4)
        j += 4
        routes.append((net, mask, gateway))
    if j != (i + length + 2):
        logger.Error("Unable to parse routes")
    return routes

def ParseIpAddress(response, option, i, length, bytesReceived):
    if i + 5 < bytesReceived:
        if length != 4:
            logger.Error("Endpoint or Default Gateway not 4 bytes")
            return None
        addr = UnpackBigEndian(response, i + 2, 4)
        IpAddress = IntegerToIpAddressV4String(addr)
        return IpAddress
    else:
        logger.Error("Data too small for option:{0}", str(option))
    return None

def ParseDhcpResponse(response):
    """
    Parse DHCP response:
    Returns endpoint server or None on error.
    """
    logger.Verbose("parse Dhcp Response")
    bytesReceived = len(response)
    endpoint = None
    gateway = None
    routes = None

    # Walk all the returned options, parsing out what we need, ignoring the 
    # others. We need the custom option 245 to find the the endpoint we talk to,
    # as well as, to handle some Linux DHCP client incompatibilities,
    # options 3 for default gateway and 249 for routes. And 255 is end.

    i = 0xF0 # offset to first option
    while i < bytesReceived:
        option = Ord(response[i])
        length = 0
        if (i + 1) < bytesReceived:
            length = Ord(response[i + 1])
        logger.Verbose("DHCP option {0} at offset:{1} with length:{2}",
                       hex(option), 
                       hex(i), 
                       hex(length))
        if option == 255:
            logger.Verbose("DHCP packet ended at offset:{0}", hex(i))
            break
        elif option == 249:
            routes = ParseRoute(response, option, i, length, bytesReceived)
        elif option == 3:
            gateway = ParseIpAddress(response, option, i, length, bytesReceived)
            logger.Verbose("Default gateway:{0}, at {1}",
                           gateway, 
                           hex(i))
        elif option == 245:
            endpoint = ParseIpAddress(response, option, i, length, bytesReceived)
            logger.Verbose("Azure wire protocol endpoint:{0}, at {1}",
                           gateway, 
                           hex(i))
        else:
            logger.Verbose("Skipping DHCP option:{0} at {1} with length {2}",
                           hex(option),
                           hex(i),
                           hex(length))
        i += length + 2
    return endpoint, gateway, routes


def AllowBroadcastForDhcp(func):
    """
    Temporary allow broadcase for dhcp. Remove the route when done.
    """
    def Wrapper(*args, **kwargs):
        routeAdded = CurrOS.SetBroadcastRouteForDhcp()
        result = func(*args, **kwargs)
        if routeAdded:
            CurrOS.RemoveBroadcastRouteForDhcp()
        return result
    return Wrapper

def DisableDhcpServiceIfNeeded(func):
    """
    In some distros, dhcp service needs to be shutdown before agent probe
    endpoint through dhcp.
    """
    def Wrapper(*args, **kwargs):
        if CurrOS.IsDhcpEnabled():
            CurrOS.StopDhcpService()
            result = func(*args, **kwargs)
            CurrOS.StartDhcpService()
            return result
        else:
            return func(*args, **kwargs)
    return Wrapper

__SleepDuration = [0, 10, 30, 60, 60]

@AllowBroadcastForDhcp
@DisableDhcpServiceIfNeeded
def SendDhcpRequest(request):
    sock = None
    for duration in __SleepDuration:
        try:
            CurrOS.OpenPortForDhcp()
            CurrOS.StartNetwork()
            response = _SendDhcpRequest(request)
            ValidateDhcpResponse(request, response)
            return response
        except Exception, e:
            logger.Error("Failed to send DHCP request: {0}", e)
            return None
        finally:
            if sock:
                sock.close()
        time.sleep(duration)

def _SendDhcpRequest(request):
    sock = socket.socket(socket.AF_INET, 
                         socket.SOCK_DGRAM, 
                         socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 68)) 
    sock.sendto(request, ("<broadcast>", 67))
    sock.settimeout(10)
    logger.Info("Send DHCP request: Setting socket.timeout=10, "
                "entering recv")
    response = sock.recv(1024)
    return response

def BuildDhcpRequest(macAddress):
    """
    Build DHCP request string.
    """
    #
    # typedef struct _DHCP {
    #     UINT8   Opcode;                    /* op:    BOOTREQUEST or BOOTREPLY */
    #     UINT8   HardwareAddressType;       /* htype: ethernet */
    #     UINT8   HardwareAddressLength;     /* hlen:  6 (48 bit mac address) */
    #     UINT8   Hops;                      /* hops:  0 */
    #     UINT8   TransactionID[4];          /* xid:   random */
    #     UINT8   Seconds[2];                /* secs:  0 */
    #     UINT8   Flags[2];                  /* flags: 0 or 0x8000 for broadcast */
    #     UINT8   ClientIpAddress[4];        /* ciaddr: 0 */
    #     UINT8   YourIpAddress[4];          /* yiaddr: 0 */
    #     UINT8   ServerIpAddress[4];        /* siaddr: 0 */
    #     UINT8   RelayAgentIpAddress[4];    /* giaddr: 0 */
    #     UINT8   ClientHardwareAddress[16]; /* chaddr: 6 byte eth MAC address */
    #     UINT8   ServerName[64];            /* sname:  0 */
    #     UINT8   BootFileName[128];         /* file:   0  */
    #     UINT8   MagicCookie[4];            /*   99  130   83   99 */
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

    transactionID = GenTransactionId()

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3):
        request[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4):
        request[4 + a] = Ord(transactionID[a])

    logger.Verbose("BuildDhcpRequest: transactionId:%s,%04X" % (
                   HexDump2(transactionID), 
                   UnpackBigEndian(request, 4, 4)))

    # fill in ClientHardwareAddress
    for a in range(0, 6):
        request[0x1C + a] = Ord(macAddress[a])

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8):
        request[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("B", request)

def GenTransactionId():
    return os.urandom(4)
