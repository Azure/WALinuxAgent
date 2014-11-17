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
import string
import struct

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

def IsInRangeInclusive(a, low, high):
    """
    Return True if 'a' in 'low' <= a >= 'high'
    """
    return (a >= low and a <= high)

def IsPrintable(ch):
    """
    Return True if character is displayable.
    """
    return (IsInRangeInclusive(ch, Ord('A'), Ord('Z')) 
           or IsInRangeInclusive(ch, Ord('a'), Ord('z')) 
           or IsInRangeInclusive(ch, Ord('0'), Ord('9')))

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
        if Ord(a[offset]) != Ord(b[offset]):
            return False
    return True

def IntegerToIpAddressV4String(a):
    """
    Build DHCP request string.
    """
    return "%u.%u.%u.%u" % ((a >> 24) & 0xFF, 
                            (a >> 16) & 0xFF, 
                            (a >> 8) & 0xFF, 
                            (a) & 0xFF)

def Ascii(val):
    uni = None
    if type(val) == str:
        uni = unicode(val, 'utf-8', errors='ignore') 
    else:
        uni = unicode(val)
    if uni is None:
        return '<Unsupported charset>'
    else:
        return uni.encode('ascii', 'backslashreplace')


def HexStringToByteArray(a):
    """
    Return hex string packed into a binary struct.
    """
    b = b""
    for c in range(0, len(a) // 2):
        b += struct.pack("B", int(a[c * 2:c * 2 + 2], 16))
    return b

def SetSshConfig(config, name, val):
    notfound = True
    for i in range(0, len(config)):
        if config[i].startswith(name):
            config[i] = "{0} {1}".format(name, val)
            notfound = False
        elif config[i].startswith("Match"):
            #Match block must be put in the end of sshd config
            break
    if notfound:
        config.insert(i, "{0} {1}".format(name, val))
    return config

def RemoveBom(c):
    if ord(c[0]) > 128 and ord(c[1]) > 128 and ord(c[2] > 128):
        c = c[3:]
    return c
