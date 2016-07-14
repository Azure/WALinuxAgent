from tests.tools import *
import azurelinuxagent.common.osutil as osutil
import azurelinuxagent.common.dhcp as dhcp
import azurelinuxagent.common.protocol as protocol
import azurelinuxagent.pa.provision as provision
import azurelinuxagent.pa.deprovision as deprovision
import azurelinuxagent.daemon as daemon
import azurelinuxagent.daemon.resourcedisk as resourcedisk
import azurelinuxagent.daemon.scvmm as scvmm
import azurelinuxagent.ga.exthandlers as exthandlers
import azurelinuxagent.ga.monitor as monitor
import azurelinuxagent.ga.update as update

class TestImportHandler(AgentTestCase):
    def test_get_handler(self):
        osutil.get_osutil()
        protocol.get_protocol_util()
        dhcp.get_dhcp_handler()
        provision.get_provision_handler()
        deprovision.get_deprovision_handler()
        daemon.get_daemon_handler()
        resourcedisk.get_resourcedisk_handler()
        scvmm.get_scvmm_handler()
        monitor.get_monitor_handler()
        update.get_update_handler()
        exthandlers.get_exthandlers_handler()
