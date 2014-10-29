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


def FindFirstNode(xmlDoc, selector):
    nodes = FindAllNodes(xmlDoc, selector)
    if len(nodes) > 0:
        return nodes[0]

def FindAllNodes(xmlDoc, selector):
    nodes = xmlDoc.findall(selector)
    return nodes

def GetNodeTextData(a):
    """
    Filter non-text nodes from DOM tree
    """
    for b in a.childNodes:
        if b.nodeType == b.TEXT_NODE:
            return b.data

def Unpack(buf, offset, range):
    """
    Unpack bytes into python values.
    """
    result = 0
    for i in range:
        result = (result << 8) | Ord(buf[offset + i])
    return result

def UnpackLittleEndian(buf, offset, length):
    """
    Unpack little endian bytes into python values.
    """
    return Unpack(buf, offset, list(range(length - 1, -1, -1)))

def UnpackBigEndian(buf, offset, length):
    """
    Unpack big endian bytes into python values.
    """
    return Unpack(buf, offset, list(range(0, length)))

def HexDump3(buf, offset, length):
    """
    Dump range of buf in formatted hex.
    """
    return ''.join(['%02X' % Ord(char) for char in buf[offset:offset + length]])

def HexDump2(buf):
    """
    Dump buf in formatted hex.
    """
    return HexDump3(buf, 0, len(buf))

def HexDump(buffer, size):
    """
    Return Hex formated dump of a 'buffer' of 'size'.
    """
    if size < 0:
        size = len(buffer)
    result = ""
    for i in range(0, size):
        if (i % 16) == 0:
            result += "%06X: " % i
        byte = buffer[i]
        if type(byte) == str:
            byte = ord(byte.decode('latin1'))
        result += "%02X " % byte
        if (i & 15) == 7:
            result += " "
        if ((i + 1) % 16) == 0 or (i + 1) == size:
            j = i
            while ((j + 1) % 16) != 0:
                result += "   "
                if (j & 7) == 7:
                    result += " "
                j += 1
            result += " "
            for j in range(i - (i % 16), i + 1):
                byte=buffer[j]
                if type(byte) == str:
                    byte = ord(byte.decode('latin1'))
                k = '.'
                if IsPrintable(byte):
                    k = chr(byte)
                result += k
            if (i + 1) != size:
                result += "\n"
    return result

def Ord(a):
    """
    Allows indexing into a string or an array of integers transparently.
    Generic utility function.
    """
    if type(a) == type("a"):
        a = ord(a)
    return a

def CompareBytes(a, b, start, length):
    for offset in range(start, start + length):
        if a[offset] != b[offset]:
            return false
        return true

def IntegerToIpAddressV4String(self, a):
    """
    Build DHCP request string.
    """
    return "%u.%u.%u.%u" % ((a >> 24) & 0xFF, 
                            (a >> 16) & 0xFF, 
                            (a >> 8) & 0xFF, 
                            (a) & 0xFF)

