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

import walinuxagent.logger as logger
import walinuxagent.utils.restutil as restutil
import walinuxagent.utils.osutil as osutil
from walinuxagent.protocol.contract import *

class ProtocolV1(Protocol):

    @staticmethod
    def Detect():
        osutil.OpenPortForDhcp()
        pass

    @staticmethod
    def Init():
        return ProtocolV1()

    def __init__(self, endpoint):
        self.endpoint = endpoint

    def getVmInfo(self):
        pass

    def getCerts(self):
        pass

    def getExtensions(self):
        pass

    def getOvf(self):
        pass

    def reportProvisionStatus(self):
        pass

    def reportAgentStatus(self):
        pass

    def reportExtensionStatus(self):
        pass

    def reportEvent(self):
        pass

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
    sendData = [0] * 244

    transactionID = os.urandom(4)

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3):
        sendData[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4):
        sendData[4 + a] = Ord(transactionID[a])

    LogIfVerbose("BuildDhcpRequest: transactionId:%s,%04X" % (self.HexDump2(transactionID), self.UnpackBigEndian(sendData, 4, 4)))

    # fill in ClientHardwareAddress
    for a in range(0, 6):
        sendData[0x1C + a] = Ord(macAddress[a])

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8):
        sendData[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("B", sendData)

