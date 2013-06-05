#!/usr/bin/python

import os
import sys
import platform
import socket
import fcntl
import struct
import array
import re
import tempfile
import unittest
import random
import string
import threading
from time import ctime, sleep
import imp

# waagent has no '.py' therefore create waagent module import manually.
waagent=imp.load_source('waagent','../waagent')

TestingVersion = "$CommitBranch:future$|$LastCommitDate:2013-04-16 15:52:17 -0700$|$LastCommitHash:7ad7c643b2adbac40b1ea4a5b6eb19f0fe971623$"


class WaagentTestCases(unittest.TestCase):
    """
    Test cases for waagent
    """
    def setUp(self):
        """
        Check for root permissions.
        Check Distro is supported.
        Create a waagent.conf file.
        """
        waagent.LoggerInit('/var/log/waagent.log','/dev/console')
        if not self.AmIRoot():
            raise Exception('I need to run as root')
        DistroName=platform.dist()[0]
        self.failUnless(hasattr(waagent,DistroName+'Distro') == True,DistroName+' is not a supported linux distribution.')
        waagent.MyDistro=getattr(waagent,DistroName+'Distro')()
        # set up /etc/waagent.conf
        with open('/etc/waagent.conf','wb') as f:
            f.write(waagent.WaagentConf)
            f.close()
            
    def tearDown(self):
        """
        Remove test resources.
        This is a stub
        """
        pass

    def AmIRoot(self):
        """
        Check that our uid is root.
        """
        return 'root' in waagent.RunGetOutput('id')[1]

    def writetothelog(self,id):
        """
        Convienence function.
        Used by testTwoLogWritingThreads()
        Write 'start', sleep for id seconds and
        write 'end' to the logfile.
        """
        waagent.Log(str(id)+' start ')
        sleep(id)
        waagent.Log(str(id)+' end  ')

    def noop(self,arg2):
        """
        Set a method to noop() to prevent its operation.
        """
        pass

##############TESTCASES##########################

###############Astract Distro - Concrete Distro Tests##############

    def testMyDistroMemberVariables(self):
        """
        Ensure that required Distro properties are not None.
        """
        assert  waagent.MyDistro.agent_service_name is not None , 'MyDistro.agent_service_name must not be None'
        assert  waagent.MyDistro.selinux is not None , 'MyDistro.selinux must not be None'
        assert  waagent.MyDistro.ssh_service_name is not None , 'MyDistro.ssh_service_name must not be None'
        assert  waagent.MyDistro.ssh_config_file is not None , 'MyDistro.ssh_config_file must not be None'
        assert  waagent.MyDistro.hostname_file_path is not None , 'MyDistro.hostname_file_path must not be None'
        assert  waagent.MyDistro.dhcp_client_name is not None , 'MyDistro.dhcp_client_name must not be None'
        assert  waagent.MyDistro.requiredDeps is not None , 'MyDistro.requiredDeps must not be None'
        assert  waagent.MyDistro.init_script_file is not None , 'MyDistro.init_script_file must not be None'
        assert  waagent.MyDistro.agent_package_name is not None , 'MyDistro.agent_package_name must not be None'
        assert  waagent.MyDistro.fileBlackList is not None , 'MyDistro.fileBlackList must not be None'
        assert  waagent.MyDistro.agent_files_to_uninstall is not None , 'MyDistro.agent_files_to_uninstall must not be None'
        assert  waagent.MyDistro.grubKernelBootOptionsFile is not None , 'MyDistro.grubKernelBootOptionsFile must not be None'
        assert  waagent.MyDistro.grubKernelBootOptionsLine is not None , 'MyDistro.grubKernelBootOptionsLine must not be None'


    def testMyDistro_restartSshService(self):
        """
        Test MyDistro.restartSshService()
        """
        cmd = 'service '+ waagent.MyDistro.ssh_service_name + ' status'
        sshpid=string.rsplit(waagent.RunGetOutput(cmd)[1],' ',1)
        waagent.MyDistro.restartSshService()
        assert sshpid is not string.rsplit(waagent.RunGetOutput(cmd)[1],' ',1),'ssh server pid is unchanged.'

#     def testMyDistro_checkPackageInstalled(self):
#         """MyDistro can check if WaLinuxAgent package is installed"""
#         assert waagent.MyDistro.checkPackageInstalled(waagent.MyDistro.agent_package_name) != 0, waagent.MyDistro.agent_package_name+' is Not Installed.'

#     def testMyDistro_checkPackageUpdateable(self):
#         """MyDistro can check if WaLinuxAgent package is updateable to new version."""
#         assert waagent.MyDistro.checkPackageUpdateable(waagent.MyDistro.agent_package_name) == 0 , waagent.MyDistro.agent_package_name+' is not updateable.'

    
    def testMyDistro_isSelinuxSystem(self):
        """
        MyDistro can perform Selinux operations.
        Test MyDistro.isSelinuxSystem, if true then also test:
        MyDistro.isSelinuxRunning
        MyDistro.setSelinuxEnforce
        MyDistro.setSelinuxContext
        """
        selinux=waagent.MyDistro.isSelinuxSystem()
        if selinux:
            assert waagent.MyDistro.isSelinuxRunning(), 'Selinux not running.'
            assert waagent.MyDistro.setSelinuxEnforce(0), 'Unable to call setenforce(0).'
            assert waagent.MyDistro.setSelinuxContext('./test_waagent.py','unconfined_u:object_r:ssh_home_t:s0'), 'Unable to set Selinux context.'
            assert waagent.MyDistro.setSelinuxEnforce(0), 'Unable to call setenforce(1).'
        else:
            print 'Selinux not installed. - skipping Selinux tests'
        
    def testMyDistro_load_unload_ata_piix(self):
        """
        Attempt to insert and remove ata_piix.ko
        by calling MyDistro.load_ata_piix
        and MyDistro.unload_ata_piix.
        """
        assert waagent.MyDistro.load_ata_piix() == 0, 'Unable to load ata_piix.ko.'
        assert waagent.MyDistro.unload_ata_piix() == 0, 'Unable to unload ata_piix.ko.'
        
    def testMyDistro_publishHostname(self):
        """
        Test MyDistro.publishHostname
        on success, the distro dependent config
        contains the hostname, but currently
        this test suceeds if the config files were written
        without error.
        """
        assert waagent.MyDistro.publishHostname('LENG') == 0, 'Error setting hostname to LENG.'

#     def testMyDistro_registerAgentService(self):
#         assert waagent.MyDistro.registerAgentService() == 0, 'Unable to register agent as service.'

    def testMyDistro_setHostname(self):
        """
        Test MyDistro.setHostname.
        Successfull if hostname is changed.
        Reset hostname when finished.
        """
        code,oldname = waagent.RunGetOutput('hostname')
        waagent.MyDistro.setHostname('HOSTNAMETEST')
        code,newname = waagent.RunGetOutput('hostname')
        assert 'HOSTNAMETEST' == newname.strip(), 'Unable to set hostname.'
        waagent.MyDistro.setHostname(oldname)

    def testMyDistro_checkDependencies(self):
        """
        Test MyDistro.checkDependencies succeeds
        """
        assert waagent.MyDistro.checkDependencies() == 0 , 'Dependency Check failed.'
        
    def testMyDistro_startAgentService(self):
        """
        Test MyDistro.startAgentService.
        """
        assert waagent.MyDistro.startAgentService() == 0, 'Unable to start ' + waagent.MyDistro.agent_service_name

    def testMyDistro_stopAgentService(self):
        """
        Test MyDistro.stopAgentService.
        """
        assert waagent.MyDistro.stopAgentService() == 0, 'Unable to stop ' + waagent.MyDistro.agent_service_name
         
    def testMyDistro_deleteRootPassword(self):
        """
        Test MyDistro.deleteRootPassword.
        Restore the shadow file to previous state when finished.
        """
        #copy the shadow
        waagent.Run('cp /etc/shadow /etc/shadow.keep')
        waagent.MyDistro.deleteRootPassword()
        assert waagent.Run('grep LOCK /etc/shadow') == 0 , 'Error removing root password.'
        # put shadow back 
        waagent.Run('mv /etc/shadow.keep /etc/shadow')
        
    def testFindIn_AppendTo_RemoveFrom_LinuxKernelCmdline(self):
        """
        Test LinuxKernelCmdline operations.
        Search for 'splish=splash' in the kernel boot options, expect fail.
        Add 'splish=splash'.  Search for splish=splash expect success.
        Remove 'splish=splash', confirm splish=splash absent
        """
        m=waagent.FindInLinuxKernelCmdline('splish=splash')
        assert not m, '"splish=splash" was found before i put it there!!! edit it to remove "splish=splash" please.'
        
        waagent.AppendToLinuxKernelCmdline('splish=splash')
        m=waagent.FindInLinuxKernelCmdline('splish=splash')
        assert m, 'AppendToLinuxKernelCmdline failed, "splish=splash" still not found.'

        waagent.RemoveFromLinuxKernelCmdline('splish=splash')
        m=waagent.FindInLinuxKernelCmdline('splish=splash')
        assert not m, 'RemoveFromLinuxKernelCmdline failed, "splish=splash" still found.'

###############Generic waagent tests##############

    def testLogFile(self):
        """
        Write a random number with waagent.Log() and read it back.
        """
        rnds=str(random.random())
        waagent.Log('testLogFile: '+rnds)
        found = rnds in (open('/var/log/waagent.log','rb').read())
        assert found,'Unable to find '+rnds+' in /var/log/waagent.log'
        
    def testFindReplaceStringInFile(self):
        """
        Test file/string operations using
        string literals and regular expressions.
        Tests:
        FindStringInFile
        ReplaceStringInFile
        
        """
        fn='/tmp/junk'
        if os.path.exists(fn):
            os.remove(fn)
        sp='splish splash'
        yb='yabba dabba do'
        open(fn,'wb').write(sp+' I was taking a bath.')
        m=waagent.FindStringInFile(fn,sp)
        assert m is not None,'waagent.FindStringInFile() Failed: '+sp+' not found in ' + fn + '.'
        src=r'^(.*)('+sp+')(.*)$'
        rpl=r'\1 '+sp+'\2 '+yb+' \3'
        waagent.ReplaceStringInFile(fn,src,rpl)
        m=waagent.FindStringInFile(fn,yb)
        assert m is not None,'waagent.ReplaceStringInFile() Failed: '+yb+' not found in ' + fn + '.'

    def testGetFirstActiveNetworkInterfaceNonLoopback(self):
        """
        Test GetFirstActiveNetworkInterfaceNonLoopback.
        Fail if iface is 'lo'
        """
        addr='null'
        iface=waagent.GetFirstActiveNetworkInterfaceNonLoopback()[0]
        addr=waagent.GetFirstActiveNetworkInterfaceNonLoopback()[1]
        assert len(iface)>1,'Interface name too short'
        assert iface is not 'lo','Loopback Interface was returned'
        print 'iface=' + iface + ' addr=' + addr

    def testTwoLogWritingThreads(self):
        """
        Test that two threads writing to the same log
        function do not block or scramble messages.
        TODO - there is no check for success !!!
        """
        for j in range(5):
            t1=threading.Thread(target=self.writetothelog,args=(4,))
            t2=threading.Thread(target=self.writetothelog,args=(2,))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

    def testCertificatesParse(self):
        """
        TODO - need cert xml from test...
        """
        pass
    
    def testSharedConfigParse(self):
        
        """
        Test SharedConfig().Parse returns without error.
        """
        assert waagent.SharedConfig().Parse(SHAREDCONFIG), 'Error parsing SharedConfig.xml'


    def testOvfEnvParse(self):
        """
        Test OvfEnv().Parse returns without error.
        """
        assert waagent.OvfEnv().Parse(OVFXML) is not None , 'Failed to Parse ovfxml'

    def testOvfEnvProcess(self):
        """
        We expect the /var/lib/waagent/Certificates.p7m file exists.
        Test ovfenv.Process() return other than None.
        """
        assert os.path.exists('/var/lib/waagent/Certificates.p7m') , 'We expect the /var/lib/waagent/Certificates.p7m file exists.'
        waagent.WaAgent = waagent.Agent()
        ovfenv=waagent.OvfEnv().Parse(OVFXML)
        waagent.WaAgent.EnvMonitor = waagent.EnvMonitor()
        assert ovfenv.Process() is None , 'Failed to Process ovfxml'
        waagent.Run("userdel -f -r myUserName")
        
    def testAgentProvision(self):
        """
        TODO - Test Provision in non-fabric environment
        """
        waagent.verbose = True
        waagent.WaAgent = waagent.Agent()
        waagent.WaAgent.EnvMonitor = waagent.EnvMonitor()
        waagent.Config = waagent.ConfigurationProvider()
        # we cant report our role unless we have one.
        waagent.WaAgent.ReportRoleProperties=self.noop
        err=waagent.WaAgent.Provision()
        assert err == None, 'Provision Failed error ' + str(err)
        

########################################
    


OVFXML="""<?xml version="1.0" encoding="utf-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:wa="http://schemas.microsoft.com/windowsazure" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

    <wa:ProvisioningSection><wa:Version>1.0</wa:Version><LinuxProvisioningConfigurationSet xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType><HostName>egub13-vm</HostName><UserName>myUserName</UserName><UserPassword>mypassword</UserPassword><DisableSshPasswordAuthentication>false</DisableSshPasswordAuthentication><SSH><PublicKeys><PublicKey><Fingerprint>2D97B25D49B98ECC90BF1600D66D68799CFB361E</Fingerprint><Path>/home/myUserName/.ssh/authorized_keys</Path></PublicKey></PublicKeys></SSH></LinuxProvisioningConfigurationSet></wa:ProvisioningSection>

  <wa:PlatformSettingsSection><wa:Version>1.0</wa:Version><PlatformSettings xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><KmsServerHostname>kms.core.windows.net</KmsServerHostname></PlatformSettings></wa:PlatformSettingsSection>
</Environment>
"""

SHAREDCONFIG="""
<SharedConfig version="1.0.0.0" goalStateIncarnation="1">
  <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
    <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
    <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
  </Deployment>
  <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
  <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" settleTimeSeconds="10" />
  <LoadBalancerSettings timeoutSeconds="0" waitLoadBalancerProbeCount="8">
    <Probes>
      <Probe name="MachineRole" />
      <Probe name="55B17C5E41A1E1E8FA991CF80FAC8E55" />
      <Probe name="3EA4DBC19418F0A766A4C19D431FA45F" />
    </Probes>
  </LoadBalancerSettings>
  <OutputEndpoints>
    <Endpoint name="MachineRole:Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" type="SFS">
      <Target instance="MachineRole_IN_0" endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
    </Endpoint>
  </OutputEndpoints>
  <Instances>
    <Instance id="MachineRole_IN_0" address="10.115.153.75">
      <FaultDomains randomId="0" updateId="0" updateCount="0" />
      <InputEndpoints>
        <Endpoint name="a" address="10.115.153.75:80" protocol="http" isPublic="true" loadBalancedPublicAddress="70.37.106.197:80" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="80" to="80" />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" address="10.115.153.75:3389" protocol="tcp" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="3389" to="3389" />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput" address="10.115.153.75:20000" protocol="tcp" isPublic="true" loadBalancedPublicAddress="70.37.106.197:3389" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="20000" to="20000" />
          </LocalPorts>
        </Endpoint>
      </InputEndpoints>
    </Instance>
  </Instances>
</SharedConfig>
"""


if __name__ == '__main__':
    s=unittest.TestLoader().loadTestsFromTestCase(WaagentTestCases)
    unittest.TextTestRunner(verbosity=2).run(s)
    #    import cProfile
    #    cProfile.run('unittest.TextTestRunner(verbosity=2).run(s)','profile.out')

