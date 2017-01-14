# Microsoft Azure Linux Agent
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

import base64
import crypt
import random
import string
import struct
import sys
import xml.dom.minidom as minidom

from distutils.version import LooseVersion as Version


def parse_doc(xml_text):
    """
    Parse xml document from string
    """
    # The minidom lib has some issue with unicode in python2.
    # Encode the string into utf-8 first
    xml_text = xml_text.encode('utf-8')
    return minidom.parseString(xml_text)


def findall(root, tag, namespace=None):
    """
    Get all nodes by tag and namespace under Node root.
    """
    if root is None:
        return []

    if namespace is None:
        return root.getElementsByTagName(tag)
    else:
        return root.getElementsByTagNameNS(namespace, tag)


def find(root, tag, namespace=None):
    """
    Get first node by tag and namespace under Node root.
    """
    nodes = findall(root, tag, namespace=namespace)
    if nodes is not None and len(nodes) >= 1:
        return nodes[0]
    else:
        return None


def gettext(node):
    """
    Get node text
    """
    if node is None:
        return None

    for child in node.childNodes:
        if child.nodeType == child.TEXT_NODE:
            return child.data
    return None


def findtext(root, tag, namespace=None):
    """
    Get text of node by tag and namespace under Node root.
    """
    node = find(root, tag, namespace=namespace)
    return gettext(node)


def getattrib(node, attr_name):
    """
    Get attribute of xml node
    """
    if node is not None:
        return node.getAttribute(attr_name)
    else:
        return None


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
                byte = buffer[j]
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
    if type(a) == type(b'') or type(a) == type(u''):
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


def hexstr_to_bytearray(a):
    """
    Return hex string packed into a binary struct.
    """
    b = b""
    for c in range(0, len(a) // 2):
        b += struct.pack("B", int(a[c * 2:c * 2 + 2], 16))
    return b


def set_ssh_config(config, name, val):
    found = False
    no_match = -1

    match_start = no_match
    for i in range(0, len(config)):
        if config[i].startswith(name) and match_start == no_match:
            config[i] = "{0} {1}".format(name, val)
            found = True
        elif config[i].lower().startswith("match"):
            if config[i].lower().startswith("match all"):
                # outside match block
                match_start = no_match
            elif match_start == no_match:
                # inside match block
                match_start = i
    if not found:
        if match_start != no_match:
            i = match_start
        config.insert(i, "{0} {1}".format(name, val))
    return config


def set_ini_config(config, name, val):
    notfound = True
    nameEqual = name + '='
    length = len(config)
    text = "{0}=\"{1}\"".format(name, val)

    for i in reversed(range(0, length)):
        if config[i].startswith(nameEqual):
            config[i] = text
            notfound = False
            break

    if notfound:
        config.insert(length - 1, text)


def remove_bom(c):
    '''
    bom is comprised of a sequence of three chars,0xef, 0xbb, 0xbf, in case of utf-8.
    '''
    if not is_str_none_or_whitespace(c) and \
       len(c) > 2 and \
       str_to_ord(c[0]) > 128 and \
       str_to_ord(c[1]) > 128 and \
       str_to_ord(c[2]) > 128:
        c = c[3:]
    return c


def gen_password_hash(password, crypt_id, salt_len):
    collection = string.ascii_letters + string.digits
    salt = ''.join(random.choice(collection) for _ in range(salt_len))
    salt = "${0}${1}".format(crypt_id, salt)
    if sys.version_info[0] == 2:
        # if python 2.*, encode to type 'str' to prevent Unicode Encode Error from crypt.crypt
        password = password.encode('utf-8')
    return crypt.crypt(password, salt)


def get_bytes_from_pem(pem_str):
    base64_bytes = ""
    for line in pem_str.split('\n'):
        if "----" not in line:
            base64_bytes += line
    return base64_bytes


def b64encode(s):
    from azurelinuxagent.common.version import PY_VERSION_MAJOR
    if PY_VERSION_MAJOR > 2:
        return base64.b64encode(bytes(s, 'utf-8')).decode('utf-8')
    return base64.b64encode(s)


def b64decode(s):
    from azurelinuxagent.common.version import PY_VERSION_MAJOR
    if PY_VERSION_MAJOR > 2:
        return base64.b64decode(s).decode('utf-8')
    return base64.b64decode(s)


def safe_shlex_split(s):
    import shlex
    from azurelinuxagent.common.version import PY_VERSION
    if PY_VERSION[:2] == (2, 6):
        return shlex.split(s.encode('utf-8'))
    return shlex.split(s)


def parse_json(json_str):
    """
    Parse json string and return a resulting dictionary
    """
    # trim null and whitespaces
    result = None
    if not is_str_none_or_whitespace(json_str):
        import json
        result = json.loads(json_str.rstrip(' \t\r\n\0'))

    return result

def is_str_none_or_whitespace(s):
    return s is None or len(s) == 0 or s.isspace()
