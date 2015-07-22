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

import crypt
import random
import string
import struct

def find_first_node(xml_doc, selector, ns=None):
    nodes = find_all_nodes(xml_doc, selector, ns=ns)
    if len(nodes) > 0:
        return nodes[0]

def find_all_nodes(xml_doc, selector, ns=None):
    nodes = xml_doc.findall(selector, ns)
    return nodes

def find_text(root, selector, ns=None, default=None):
    element = root.find(selector, ns)
    if element is not None:
        return element.text
    else:
        return default

def get_node_text(a):
    """
    Filter non-text nodes from DOM tree
    """
    for b in a.childNodes:
        if b.nodeType == b.TEXT_NODE:
            return b.data

def unpack(buf, offset, range):
    """
    Unpack bytes into python values.
    """
    result = 0
    for i in range:
        result = (result << 8) | str_to_ord(buf[offset + i])
    return result

def unpack_little_endian(buf, offset, length):
    """
    Unpack little endian bytes into python values.
    """
    return unpack(buf, offset, list(range(length - 1, -1, -1)))

def unpack_big_endian(buf, offset, length):
    """
    Unpack big endian bytes into python values.
    """
    return unpack(buf, offset, list(range(0, length)))

def hex_dump3(buf, offset, length):
    """
    Dump range of buf in formatted hex.
    """
    return ''.join(['%02X' % str_to_ord(char) for char in buf[offset:offset + length]])

def hex_dump2(buf):
    """
    Dump buf in formatted hex.
    """
    return hex_dump3(buf, 0, len(buf))

def is_in_range(a, low, high):
    """
    Return True if 'a' in 'low' <= a >= 'high'
    """
    return (a >= low and a <= high)

def is_printable(ch):
    """
    Return True if character is displayable.
    """
    return (is_in_range(ch, str_to_ord('A'), str_to_ord('Z'))
           or is_in_range(ch, str_to_ord('a'), str_to_ord('z'))
           or is_in_range(ch, str_to_ord('0'), str_to_ord('9')))

def hex_dump(buffer, size):
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
                    byte = str_to_ord(byte.decode('latin1'))
                k = '.'
                if is_printable(byte):
                    k = chr(byte)
                result += k
            if (i + 1) != size:
                result += "\n"
    return result

def str_to_ord(a):
    """
    Allows indexing into a string or an array of integers transparently.
    Generic utility function.
    """
    if type(a) == type("a"):
        a = ord(a)
    return a

def compare_bytes(a, b, start, length):
    for offset in range(start, start + length):
        if str_to_ord(a[offset]) != str_to_ord(b[offset]):
            return False
    return True

def int_to_ip4_addr(a):
    """
    Build DHCP request string.
    """
    return "%u.%u.%u.%u" % ((a >> 24) & 0xFF,
                            (a >> 16) & 0xFF,
                            (a >> 8) & 0xFF,
                            (a) & 0xFF)

def ascii(val):
    uni = None
    if type(val) == str:
        uni = unicode(val, 'utf-8', errors='ignore')
    else:
        uni = unicode(val)
    if uni is None:
        raise ValueError('<Unsupported charset>')
    else:
        return uni.encode('ascii', 'backslashreplace')

def hexstr_to_bytearray(a):
    """
    Return hex string packed into a binary struct.
    """
    b = b""
    for c in range(0, len(a) // 2):
        b += struct.pack("B", int(a[c * 2:c * 2 + 2], 16))
    return b

def set_ssh_config(config, name, val):
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

def remove_bom(c):
    if str_to_ord(c[0]) > 128 and str_to_ord(c[1]) > 128 and str_to_ord(c[2]) > 128:
        c = c[3:]
    return c

def gen_password_hash(password, use_salt, salt_type, salt_len):
        salt="$6$"
        if use_salt:
            collection = string.ascii_letters + string.digits
            salt = ''.join(random.choice(collection) for _ in range(salt_len))
            salt = "${0}${1}".format(salt_type, salt)
        return crypt.crypt(password, salt)

def num_to_bytes(i):
        """
        Pack number into bytes.  Retun as string.
        """
        result = []
        while i:
            result.append(chr(i & 0xFF))
            i >>= 8
        result.reverse()
        return ''.join(result)

def bits_to_str(a):
    """
    Return string representation of bits in a.
    """
    index=7
    s = ""
    c = 0
    for bit in a:
        c = c | (bit << index)
        index = index - 1
        if index == -1:
            s = s + struct.pack('>B', c)
            c = 0
            index = 7
    return s

