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
import os
import json
import time
import subprocess
import signal
import sys
import zipfile
from azurelinuxagent.common.exception import UpdateError, ProtocolError
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
from azurelinuxagent.common.event import add_event
from azurelinuxagent.common.future import ustr
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.restutil as restutil
from azurelinuxagent.common.version import AGENT_VERSION
from azurelinuxagent.common.utils.textutil import Version
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.protocol import get_protocol_util

def get_update_handler():
    return UpdateHandler()

GA_DIR = 'GuestAgent' # Dir name for guest agent bin and data
GA_ERR = 'error' # File name for guest agent error record
MAX_FAILURE = 3 # Max failure allowed for guest agent before blacklisted
RETAIN_INTERVAL = 24 * 60 * 60 # Retain interval for black list

"""
Handles self update logic
"""
class UpdateHandler(object):

    def __init__(self):
        self.osutil = get_osutil()
        self.protocol_util = get_protocol_util()
        self.last_etag = None
        self.agents = []
        self.error_record = {}

    def run(self):
        """
        1. If self-update is enabled, check for new versions.
           otherwise, use current agent
        2. Invoke run-exthandlers task
        """
        self.mk_ga_dir()

        self.load_error_record() 

        updated = self.check_for_update()
        if not updated:
            return 

        latest_agent = None

        if conf.get_autoupdate_enabled():
            logger.info("Auto update enabled")
            latest_agent = self.get_latest_agent()

        try:
            self.run_extensions(latest_agent)
        except UpdateError as e:
            add_event(u"WALA", is_success=False, message=ustr(e))
            if latest_agent is not None:
                latest_agent.err.mark_failure()
        
        self.save_error_record()
    
    def mk_ga_dir(self):
        dir_path = os.path.join(conf.get_lib_dir(), GA_DIR)
        fileutil.mkdir(dir_path, mode=0o700)

    def get_latest_agent(self):
        available_agent = [agent for agent in self.agents \
                           if not agent.err.is_blacklisted()]
 
        return available_agent[0] if len(available_agent) >= 1 else None

    def run_extensions(self, latest_agent):
        agent_bin = sys.argv[0]

        if latest_agent is not None:
            logger.info(u"The latest guest agent version is : {0}", 
                        latest_agent.version)
            agent_bin = latest_agent.get_agent_bin()

            if not latest_agent.is_downloaded():
                try:
                    latest_agent.download()
                except Exception as e:
                    raise UpdateError(u"Download failed", e)

        devnull = open(os.devnull, 'w')
        try:
            child = subprocess.Popen([agent_bin, 'run-exthandlers'], 
                                      stdout=devnull, stderr=devnull)
        except Exception as e:
            raise UpdateError(u"Failed to launch task 'run-exthandlers'", e)

        ret = child.wait()
        if ret == None or ret != 0:
            msg = u"Task 'run-exthandlers' returns none-zero code: {0}".format(1)
            raise UpdateError(msg)

    def check_for_update(self):
        """Get latest version not in black list"""
        self.agents = []
        try:
            protocol = self.protocol_util.get_protocol()
            manifest_list, etag = protocol.get_vmagent_manifests()
        except ProtocolError as e:
            add_event(u"WALA", is_success=False, message=ustr(e))
            return False

        if self.last_etag is not None and self.last_etag == etag:
            logger.verb("No change to ext handler config:{0}, skip", etag)
            return False

        logger.info("Check for update")

        family = conf.get_autoupdate_gafamily()
        manifests = [manifest for manifest in manifest_list.vmAgentManifests \
                     if manifest.family == family]
        if len(manifests) == 0:
            message = u"No avaiable guest agent found for: {0}".format(family)
            add_event(u"WALA", message=message)

        try:
            pkg_list = protocol.get_vmagent_pkgs(manifests[0])
        except ProtocolError as e:
            message= u"Failed to get GA package list: {0}".format(e)
            add_event("WALA", is_success=False, message=message)
            return
        
        #Only considering versions that is larger than current
        pkgs = [pkg for pkg in pkg_list.versions \
                if Version(pkg.version) > Version(AGENT_VERSION)]
        
        pkgs = sorted(pkgs, key=lambda pkg : Version(pkg.version), reverse=True)

        for pkg in pkgs:
            ga_err = self.error_record.get(pkg.version)
            if ga_err is None:
                ga_err = GuestAgentError(version=pkg.version)
            agent = GuestAgent(pkg, ga_err)
            self.agents.append(agent)
        
        #Update error record list. 
        #Only keep the records for available agent versions
        self.error_record = {}
        for agent in self.agents:
            self.error_record[agent.version] = agent.err
        return True

    def load_error_record(self):
        self.error_record = {}
        file_path = os.path.join(conf.get_lib_dir(), GA_DIR, GA_ERR)
        if not os.path.isfile(file_path):
            return

        try:
            error_data_list = json.loads(fileutil.read_file(file_path))
            for error_data in error_data_list:
                ga_err = GuestAgentError()
                ga_err.from_dict(error_data)
                ga_err.clear_old_failure()
                self.error_record[ga_err.version] = ga_err
        except (IOError, ValueError) as e:
            message = u"Failed to load GA error record: {0}".format(e)
            add_event(u"WALA", is_success=False, message=message)

    def save_error_record(self):
        error_data_list = []
        for err in self.error_record.values():
            error_data = err.to_dict()
            error_data_list.append(error_data)

        file_path = os.path.join(conf.get_lib_dir(), GA_DIR, GA_ERR)
        try:
            fileutil.write_file(file_path, json.dumps(error_data_list))
        except (IOError, ValueError) as e:
            message = u"Failed to save GA error record: {0}".format(e)
            add_event(u"WALA", is_success=False, message=message)

class GuestAgent(object):
    def __init__(self, pkg, err):
        self.version = pkg.version
        self.pkg = pkg
        self.err = err

    def get_agent_bin(self):
        file_name = "WALinuxAgent-{0}.egg".format(self.version)
        return os.path.join(self.get_agent_dir(), file_name)

    def get_agent_dir(self):
        dir_name = "WALinuxAgent-{0}".format(self.version)
        return os.path.join(conf.get_lib_dir(), GA_DIR, dir_name)

    def get_agent_pkg_file(self):
        pkg_file_name = "WALinuxAgent-{0}.zip".format(self.version)
        return os.path.join(conf.get_lib_dir(), GA_DIR, pkg_file_name)
    
    def is_downloaded(self):
        return os.path.isfile(self.get_agent_bin())

    def download(self):
        logger.info(u"Download guest agent: {0}", self.version)
        add_event(u"WALA", message="Start downloading guest agent package")
        package = None

        for uri in self.pkg.uris:
            try:
                resp = restutil.http_get(uri.uri, chk_proxy=True)
                if resp.status == restutil.httpclient.OK:
                    package = resp.read()
                    break
            except restutil.HttpError as e:
                logger.warn("Failed download guest agent from: {0}", uri.uri)

        if package is None:
            raise UpdateError("Failed to download guest agent package")

        logger.info("Unpack guest agent package")
        pkg_file = self.get_agent_pkg_file()
        fileutil.write_file(pkg_file, bytearray(package), asbin=True)
        zipfile.ZipFile(pkg_file).extractall(self.get_agent_dir())

        add_event(name="WALA", message="Download guest agent package succeeded")

class GuestAgentError(object):
    def __init__(self, version=None, last_failure=0, failure_count=0):
        self.version = version
        self.last_failure = last_failure
        self.failure_count = failure_count
   
    def mark_failure(self):
        self.last_failure = time.time()
        self.failure_count += 1
    
    def clear_old_failure(self):
        """Clear failure recored"""
        if self.last_failure < (time.time() - RETAIN_INTERVAL):
            self.last_failure = 0
            self.failure_count = 0

    def is_blacklisted(self):
        return self.failure_count >= MAX_FAILURE
    
    def from_dict(self, data):
        self.version = data.get(u"version")
        self.last_failure = data.get(u"last_failure", 0)
        self.failure_count = data.get(u"failure_count", 0)

    def to_dict(self):
        data = {
            u"version": self.version,
            u"last_failure": self.last_failure,
            u"failure_count": self.failure_count,
        }  
        return data
