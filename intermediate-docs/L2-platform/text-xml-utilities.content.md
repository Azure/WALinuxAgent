# Compose Content for: L2-platform/text-xml-utilities.md

Total files: 1

---

## setup.py

### Structural symbols

- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.parse_doc.xml_text`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall.root`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall.tag`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findall.namespace`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find.root`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find.tag`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.find.namespace`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettext`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettext.node`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettextxml`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.gettextxml.node`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext.root`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext.tag`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.findtext.namespace`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib.node`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.getattrib.attr_name`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.hasattrib`
- `%REPO%/azurelinuxagent/common/utils/textutil.py.hasattrib.node`
- `%REPO%/az

### Source excerpt

````
# Microsoft Azure Linux Agent
#
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

import base64
import re
import struct
import sys
import traceback
import xml.dom.minidom as minidom
import zlib

from azurelinuxagent.common.future import ustr


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


def gettextxml(node):
    """
    Get the raw XML of a text node
    """
    if node is None:
        return None

    for child in node.childNodes:
        if child.nodeType == child.TEXT_NODE:
            return child.toxml()
    return None


def findtext(root, tag, namespace=None):
    """
    Get text of node by tag and namespa
````

---
