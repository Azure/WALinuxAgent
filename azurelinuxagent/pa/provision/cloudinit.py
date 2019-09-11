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
#

import dbus
import os
import os.path
import time

from datetime import datetime

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil

from azurelinuxagent.common.event import elapsed_milliseconds, WALAEventOperation
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.protocol import OVF_FILE_NAME
from azurelinuxagent.common.protocol.ovfenv import OvfEnv
from azurelinuxagent.pa.provision.default import ProvisionHandler


class CloudInitProvisionHandler(ProvisionHandler):
    def __init__(self):
        super(CloudInitProvisionHandler, self).__init__()

    def run(self):
        try:
            if super(CloudInitProvisionHandler, self).is_provisioned():
                logger.info("Provisioning already completed, skipping.")
                return

            utc_start = datetime.utcnow()
            logger.info("Running CloudInit provisioning handler")
            self.wait_for_ovfenv()
            self.protocol_util.get_protocol()
            self.report_not_ready("Provisioning", "Starting")

            thumbprint = self.wait_for_ssh_host_key()
            self.write_provisioned()
            logger.info("Finished provisioning")

            self.report_ready(thumbprint)
            self.report_event("Provisioning with cloud-init succeeded ({0}s)".format(self._get_uptime_seconds()),
                is_success=True,
                duration=elapsed_milliseconds(utc_start))

        except ProvisionError as e:
            msg = "Provisioning with cloud-init failed: {0} ({1}s)".format(ustr(e), self._get_uptime_seconds())
            logger.error(msg)
            self.report_not_ready("ProvisioningFailed", ustr(e))
            self.report_event(msg)
            return

    def wait_for_ovfenv(self, max_retry=1800, sleep_time=1):
        """
        Wait for cloud-init to copy ovf-env.xml file from provision ISO
        """
        ovf_file_path = os.path.join(conf.get_lib_dir(), OVF_FILE_NAME)
        for retry in range(0, max_retry):
            if os.path.isfile(ovf_file_path):
                try:
                    ovf_env = OvfEnv(fileutil.read_file(ovf_file_path))
                    self.handle_provision_guest_agent(ovf_env.provision_guest_agent)
                    return
                except ProtocolError as pe:
                    raise ProvisionError("OVF xml could not be parsed "
                                         "[{0}]: {1}".format(ovf_file_path,
                                                             ustr(pe)))
            else:
                if retry < max_retry - 1:
                    logger.info(
                        "Waiting for cloud-init to copy ovf-env.xml to {0} "
                        "[{1} retries remaining, "
                        "sleeping {2}s]".format(ovf_file_path,
                                                max_retry - retry,
                                                sleep_time))
                    if not self.validate_cloud_init():
                        logger.warn("cloud-init does not appear to be running")
                    time.sleep(sleep_time)
        raise ProvisionError("Giving up, ovf-env.xml was not copied to {0} "
                             "after {1}s".format(ovf_file_path,
                                                 max_retry * sleep_time))

    def wait_for_ssh_host_key(self, max_retry=1800, sleep_time=1):
        """
        Wait for cloud-init to generate ssh host key
        """
        keypair_type = conf.get_ssh_host_keypair_type()
        path = conf.get_ssh_key_public_path()
        for retry in range(0, max_retry):
            if os.path.isfile(path):
                logger.info("ssh host key found at: {0}".format(path))
                try:
                    thumbprint = self.get_ssh_host_key_thumbprint(chk_err=False)
                    logger.info("Thumbprint obtained from : {0}".format(path))
                    return thumbprint
                except ProvisionError:
                    logger.warn("Could not get thumbprint from {0}".format(path))
            if retry < max_retry - 1:
                logger.info("Waiting for ssh host key be generated at {0} "
                            "[{1} attempts remaining, "
                            "sleeping {2}s]".format(path,
                                                    max_retry - retry,
                                                    sleep_time))
                if not self.validate_cloud_init():
                    logger.warn("cloud-init does not appear to be running")
                time.sleep(sleep_time)
        raise ProvisionError("Giving up, ssh host key was not found at {0} "
                             "after {1}s".format(path,
                                                 max_retry * sleep_time))

def cloud_init_is_enabled():
    """
    Determine whether or not cloud-init is enabled.

    Args:
        None

    Returns:
        bool - True if cloud-init is enabled, False if otherwise.
    """

    unit_name = 'cloud-init-local.service'

    bus = dbus.SystemBus()
    systemd_dbus = bus.get_object(
        'org.freedesktop.systemd1',
        '/org/freedesktop/systemd1'
    )
    systemd_manager = dbus.Interface(
        systemd_dbus,
        'org.freedesktop.systemd1.Manager'
    )

    try:
        unit_is_enabled = systemd_manager.GetUnitFileState(unit_name).lower() == 'enabled'
    except dbus.DBusException as exc:
        # If the unit does not exist, then take that as a falsy
        # condition. We don't want to throw an exception in this
        # case because waagent should be able to handle the situation
        # where there is no cloud-init installed.
        if exc.get_dbus_name() == 'org.freedesktop.DBus.Error.FileNotFound':
            unit_is_enabled = False
        else:
            # Any other dbus exception should be bubbled up though.
            logger.error('Unexpected dbus error: {}'.format(exc))
            raise

    logger.info('cloud-init is enabled: {}'.format(unit_is_enabled))
    return unit_is_enabled
