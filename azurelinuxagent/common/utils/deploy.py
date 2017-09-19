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
#

import json
import os
import platform
import re
import sys

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil

from azurelinuxagent.common.osutil import get_osutil

DEPLOY_FILE = "deploy.json"
DEPLOYED_FILE = "deployed.json"


class Deploy(object):
    def __init__(self, dir=None):
        if dir is not None and not os.path.isdir(dir):
            raise Exception(u"Deploy requires a directory")

        self.dir = dir
        self._load()

    @property
    def blacklisted(self):
        return self._blacklisted

    @property
    def family(self):
        return None if self._family is None else self._family.name

    def in_partition(self, partition):
        return not self.in_safe_deployment_mode or \
            (self._family is not None and self._family.in_partition(partition))

    @property
    def in_safe_deployment_mode(self):
        return self._safe_deployment
    
    @property
    def is_deployed(self):
        return self._deployed

    def mark_deployed(self):
        before = os.path.join(self.dir, DEPLOY_FILE)
        if os.path.exists(before):
            after = os.path.join(self.dir, DEPLOYED_FILE)
            try:
                os.rename(before, after)
                self._deployed = True
            except Exception as e:
                logger.warn("Failed to rename {0} to {1}".format(before, after))

    def _load(self):
        self._blacklisted = []
        self._families = {}
        self._family = None
        self._deployed = False
        self._safe_deployment = False

        if self.dir is not None:
            path = os.path.join(self.dir, DEPLOY_FILE)
            if not os.path.isfile(path):
                path = os.path.join(self.dir, DEPLOYED_FILE)
                self._deployed = os.path.isfile(path)

            if os.path.isfile(path):
                self._safe_deployment = True
                try:
                    self._from_json(json.loads(fileutil.read_file(path)))
                except Exception as e:
                    logger.warn("Failed JSON parse of {0}: {1}".format(path, e))

            for family in sorted(iter(self._families.keys())):
                family = self._families[family]
                if family._is_supported:
                    self._family = family
                    break
    
    def _from_json(self, data):
        self._blacklisted = data.get('blacklisted', [])

        if 'families' in data:
            families = data['families']
            for family in families:
                self._families[family] = Family(family, families[family])

class Family(object):
    def __init__(self, name, data):
        if name is None:
            raise Exception(u"Family requires a name")
        if data is None:
            raise Exception(u"Family requires the family data")

        self.name = name
        self._from_json(data)
        self._evaluate()

    def in_partition(self, partition):
        return self._is_supported and partition < self._partition

    def _evaluate(self):
        if not self._require_64bit or get_osutil().is_64bit:
            d = ','.join(platform.linux_distribution())
            for v in self._versions:
                if re.match(v, d):
                    self._is_supported = True
                    break

    def _from_json(self, data):
        self._versions = data.get('versions', [])
        self._require_64bit = data.get('require_64bit', True)
        self._partition = data.get('partition', 0)
        self._is_supported = False
