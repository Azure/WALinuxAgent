## Microsoft Azure Linux Agent README

### INTRODUCTION

The Microsoft Azure Linux Agent (waagent) manages Linux & FreeBSD provisioning,
and VM interaction with the Azure Fabric Controller. It provides the following
functionality for Linux and FreeBSD IaaS deployments:

  * Image Provisioning
    - Creation of a user account
    - Configuring SSH authentication types
    - Deployment of SSH public keys and key pairs
    - Setting the host name
    - Publishing the host name to the platform DNS
    - Reporting SSH host key fingerprint to the platform
    - Resource Disk Management
    - Formatting and mounting the resource disk
    - Configuring swap space

  * Networking
    - Manages routes to improve compatibility with platform DHCP servers
    - Ensures the stability of the network interface name

  * Kernel
    - Configure virtual NUMA (disable for kernel <2.6.37)
    - Consume Hyper-V entropy for /dev/random
    - Configure SCSI timeouts for the root device (which could be remote)

  * Diagnostics
    - Console redirection to the serial port

  * SCVMM Deployments
    - Detect and bootstrap the VMM agent for Linux when running in a System
      Center Virtual Machine Manager 2012R2 environment

  * VM Extension
    - Inject component authored by Microsoft and Partners into Linux VM (IaaS)
      to enable software and configuration automation
    - VM Extension reference implementation on https://github.com/Azure/azure-linux-extensions


### COMMUNICATION

The information flow from the platform to the agent occurs via two channels:

  * A boot-time attached DVD for IaaS deployments.
    This DVD includes an OVF-compliant configuration file that includes all
    provisioning information other than the actual SSH keypairs.

  * A TCP endpoint exposing a REST API used to obtain deployment and topology
    configuration.


### REQUIREMENTS

The following systems have been tested and are known to work with the Azure
Linux Agent.  Please note that this list may differ from the official list
of supported systems on the Microsoft Azure Platform as described here:
http://support.microsoft.com/kb/2805216

  Supported Linux Distributions:
    * CoreOS
    * CentOS 6.2+
    * Red Hat Enterprise Linux 6.7+
    * Debian 7.0+
    * Ubuntu 12.04+
    * openSUSE 12.3+
    * SLES 11 SP2+
    * Oracle Linux 6.4+

  Other Supported Systems:
    * FreeBSD 10+ (Azure Linux Agent v2.0.10+)

Waagent depends on some system packages in order to function properly:

  * Python 2.6+
  * OpenSSL 1.0+
  * OpenSSH 5.3+
  * Filesystem utilities: sfdisk, fdisk, mkfs, parted
  * Password tools: chpasswd, sudo
  * Text processing tools: sed, grep
  * Network tools: ip-route


### INSTALLATION

Installation via your distribution's package repository is preferred.
You can also customize your own RPM or DEB packages using the configuration
files provided (see debian/README and rpm/README).

For more advanced installation options, such as installing to custom locations 
or prefixes, you can use ***setuptools*** to install from source by running:
   
    #sudo python setup.py install --register-service

You can view more installation options by running:

    #sudo python setup.py install --help

The agent's log file is kept at /var/log/waagent.log.

### UPGRADE

Upgrading via your distribution's package repository is preferred.

If upgrading manually, same with installation above by running:

    #sudo python setup.py install --force

Restart waagent service,for most of linux distributions:

    #sudo service waagent restart

For Ubuntu, use:

    #sudo service walinuxagent restart

For CoreOS, use:

    #sudo systemctl restart waagent 

The agent's log file is kept at /var/log/waagent.log.


### COMMAND LINE OPTIONS

Flags:

  -verbose: Increase verbosity of specified command

  -force: Skip interactive confirmation for some commands

Commands:

  -help: Lists the supported commands and flags.

  -deprovision: Attempt to clean the system and make it suitable for
   re-provisioning. Deletes the following:
     * All SSH host keys
       (if Provisioning.RegenerateSshHostKeyPair is 'y' in the configuration
       file)
     * Nameserver configuration in /etc/resolv.conf
     * Root password from /etc/shadow
       (if Provisioning.DeleteRootPassword is 'y' in the configuration file)
     * Cached DHCP client leases.
     * Resets host name to localhost.localdomain.

   WARNING! Deprovision does not guarantee that the image is cleared of all
   sensitive information and suitable for redistribution.

  -deprovision+user: Performs everything under deprovision (above) and also
   deletes the last provisioned user account and associated data.

  -version: Displays the version of waagent

  -serialconsole: Configures GRUB to mark ttyS0 (the first serial port) as
   the boot console. This ensures that kernel bootup logs are sent to the
   serial port and made available for debugging.

  -daemon: Run waagent as a daemon to manage interaction with the platform.
   This argument is specified to waagent in the waagent init script.

  -start: Run waagent as a background process

### CONFIGURATION

A configuration file (/etc/waagent.conf) controls the actions of
waagent. A sample configuration file is shown below:

```
Role.StateConsumer=None
Role.ConfigurationConsumer=None
Role.TopologyConsumer=None
Provisioning.Enabled=y
Provisioning.DeleteRootPassword=n
Provisioning.RegenerateSshHostKeyPair=y
Provisioning.SshHostKeyPairType=rsa
Provisioning.MonitorHostName=y
Provisioning.DecodeCustomData=n
Provisioning.ExecuteCustomData=n
Provisioning.PasswordCryptId=6
Provisioning.PasswordCryptSaltLength=10
ResourceDisk.Format=y
ResourceDisk.Filesystem=ext4
ResourceDisk.MountPoint=/mnt/resource
ResourceDisk.EnableSwap=n
ResourceDisk.SwapSizeMB=0
LBProbeResponder=y
Logs.Verbose=n
OS.RootDeviceScsiTimeout=300
OS.OpensslPath=None
HttpProxy.Host=None
HttpProxy.Port=None
```

The various configuration options are described in detail below. Configuration
options are of three types : Boolean, String or Integer. The Boolean
configuration options can be specified as "y" or "n". The special keyword "None"
may be used for some string type configuration entries as detailed below.

Configuration File Options:

Role.StateConsumer:
Type: String Default: None

If a path to an executable program is specified, it is invoked when waagent has
provisioned the image and the "Ready" state is about to be reported to the
Fabric. The argument specified to the program will be "Ready". The agent will
not wait for the program to return before continuing.

Role.ConfigurationConsumer:
Type: String Default: None

If a path to an executable program is specified, the program is invoked when the
Fabric indicates that a configuration file is available for the VM. The path to
the XML configuration file is provided as an argument to the executable. This
may be invoked multiple times whenever the configuration file changes. A sample
file is provided in the Appendix. Please note that the XML schema used in this
file may change in the future.  The current path of this file is
/var/lib/waagent/HostingEnvironmentConfig.xml.

Role.TopologyConsumer:
Type: String Default: None

If a path to an executable program is specified, the program is invoked when the
Fabric indicates that a new network topology layout is available for the VM. The
path to the XML configuration file is provided as an argument to the executable.
This may be invoked multiple times whenever the network topology changes (due to
service healing for example).  A sample file is provided in the Appendix. Please
note that the XML schema used in this file may change in the future.  The
current location of this file is /var/lib/waagent/SharedConfig.xml.

Provisioning.Enabled:
Type: Boolean Default: y

This allows the user to enable or disable the provisioning functionality in the
agent. Valid values are "y" or "n". If provisioning is disabled, SSH host and
user keys in the image are preserved and any configuration specified in the
Azure provisioning API is ignored.

Provisioning.DeleteRootPassword:
Type: Boolean Default: n

If set, the root password in the /etc/shadow file is erased during the
provisioning process.

Provisioning.RegenerateSshHostKeyPair:
Type: Boolean Default: y

If set, all SSH host key pairs (ecdsa, dsa and rsa) are deleted during the
provisioning process from /etc/ssh/. And a single fresh key pair is generated.
The encryption type for the fresh key pair is configurable by the
Provisioning.SshHostKeyPairType entry. Please note that some distributions will
re-create SSH key pairs for any missing encryption types when the SSH daemon is
restarted (for example, upon a reboot).

Provisioning.SshHostKeyPairType:
Type: String Default: rsa

This can be set to an encryption algorithm type that is supported by the SSH
daemon on the VM. The typically supported values are "rsa", "dsa" and "ecdsa".
Note that "putty.exe" on Windows does not support "ecdsa". So, if you intend to
use putty.exe on Windows to connect to a Linux deployment, please use "rsa" or
"dsa".

Provisioning.MonitorHostName:
Type: Boolean Default: y

If set, waagent will monitor the Linux VM for hostname changes (as returned by
the "hostname" command) and automatically update the networking configuration in
the image to reflect the change. In order to push the name change to the DNS
servers, networking will be restarted in the VM. This will result in brief loss
of Internet connectivity.

Provisioning.DecodeCustomData:
Type: Boolean Default: n

If set, waagent will decode CustomData from Base64.

Provisioning.ExecuteCustomData:
Type: Boolean Default: n

If set, waagent will execute CustomData after provisioning.

Provisioning.PasswordCryptId:
Type:String Default:6

Algorithm used by crypt when generating password hash.
    1 - MD5
    2a - Blowfish
    5 - SHA-256
    6 - SHA-512

Provisioning.PasswordCryptSaltLength
Type:String Default:10

Length of random salt used when generating password hash.

ResourceDisk.Format:
Type: Boolean Default: y

If set, the resource disk provided by the platform will be formatted and mounted
by waagent if the filesystem type requested by the user in
"ResourceDisk.Filesystem" is anything other than "ntfs". A single partition of
type Linux (83) will be made available on the disk. Note that this partition
will not be formatted if it can be successfully mounted.

ResourceDisk.Filesystem:
Type: String Default: ext4

This specifies the filesystem type for the resource disk. Supported values vary
by Linux distribution. If the string is X, then mkfs.X should be present on the
Linux image. SLES 11 images should typically use 'ext3'. FreeBSD images should
use 'ufs2' here.

ResourceDisk.MountPoint:
Type: String Default: /mnt/resource

This specifies the path at which the resource disk is mounted.

ResourceDisk.EnableSwap:
Type: Boolean Default: n

If set, a swap file (/swapfile) is created on the resource disk and added to the
system swap space.

ResourceDisk.SwapSizeMB:
Type: Integer Default: 0

The size of the swap file in megabytes.

LBProbeResponder:
Type: Boolean Default: y

If set, waagent will respond to load balancer probes from the platform (if
present).

Logs.Verbose:
Type: Boolean Default: n

If set, log verbosity is boosted. Waagent logs to /var/log/waagent.log and
leverages the system logrotate functionality to rotate logs.

OS.RootDeviceScsiTimeout:
Type: Integer Default: 300

This configures the SCSI timeout in seconds on the root device. If not set, the
system defaults are used.

OS.OpensslPath:
Type: String Default: None

This can be used to specify an alternate path for the openssl binary to use for
cryptographic operations.

HttpProxy.Host=None
HttpProxy.Port=None
Type: String Default: None

If set, agent will use proxy server to access internet

### APPENDIX

Sample Role Configuration File:

```

<?xml version="1.0" encoding="utf-8"?> <HostingEnvironmentConfig
version="1.0.0.0" goalStateIncarnation="1">
  <StoredCertificates>
    <StoredCertificate
    name="Stored0Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption"
    certificateId="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" storeName="My"
    configurationLevel="System" />
  </StoredCertificates>
  <Deployment name="a99549a92e38498f98cf2989330cd2f1"
  guid="{374ef9a2-de81-4412-ac87-e586fc869923}" incarnation="14">
    <Service name="LinuxDemo1" guid="{00000000-0000-0000-0000-000000000000}" />
    <ServiceInstance name="a99549a92e38498f98cf2989330cd2f1.4"
    guid="{250ac9df-e14c-4c5b-9cbc-f8a826ced0e7}" />
  </Deployment>
  <Incarnation number="1" instance="LinuxVM_IN_2"
  guid="{5c87ab8b-2f6a-4758-9f74-37e68c3e957b}" />
  <Role guid="{47a04da2-d0b7-26e2-f039-b1f1ab11337a}" name="LinuxVM"
  hostingEnvironmentVersion="1" software="" softwareType="ApplicationPackage"
  entryPoint="" parameters="" settleTimeSeconds="10" />
  <HostingEnvironmentSettings name="full"
  Runtime="rd_fabric_stable.111026-1712.RuntimePackage_1.0.0.9.zip">
    <CAS mode="full" />
    <PrivilegeLevel mode="max" />
    <AdditionalProperties><CgiHandlers></CgiHandlers></AdditionalProperties></HostingEnvironmentSettings>
    <ApplicationSettings>
      <Setting name="__ModelData" value="&lt;m role=&quot;LinuxVM&quot;
      xmlns=&quot;urn:azure:m:v1&quot;>&lt;r name=&quot;LinuxVM&quot;>&lt;e
      name=&quot;HTTP&quot; />&lt;e
      name=&quot;Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp&quot; />&lt;e
      name=&quot;Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput&quot;
      />&lt;e name=&quot;SSH&quot; />&lt;/r>&lt;/m>" />
      <Setting
      name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword"
      value="..." />
      <Setting
      name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountExpiration"
      value="2015-11-06T23:59:59.0000000-08:00" />
      <Setting
      name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername"
      value="rdos" />
      <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled"
      value="true" />
      <Setting name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.Enabled"
      value="true" />
      <Setting name="startpage" value="Hello World!" />
      <Setting
      name="Certificate|Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption"
      value="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" />
    </ApplicationSettings>
    <ResourceReferences>
      <Resource name="DiagnosticStore" type="directory"
      request="Microsoft.Cis.Fabric.Controller.Descriptions.ServiceDescription.Data.Policy"
      sticky="true" size="1"
      path="a99549a92e38498f98cf2989330cd2f1.LinuxVM.DiagnosticStore\"
      disableQuota="false" />
    </ResourceReferences>
  </HostingEnvironmentConfig>
```

Sample Role Topology File:

```
<?xml version="1.0" encoding="utf-8"?> <SharedConfig
version="1.0.0.0" goalStateIncarnation="2">
  <Deployment name="a99549a92e38498f98cf2989330cd2f1"
  guid="{374ef9a2-de81-4412-ac87-e586fc869923}" incarnation="14">
    <Service name="LinuxDemo1" guid="{00000000-0000-0000-0000-000000000000}" />
    <ServiceInstance name="a99549a92e38498f98cf2989330cd2f1.4"
    guid="{250ac9df-e14c-4c5b-9cbc-f8a826ced0e7}" />
  </Deployment>
  <Incarnation number="1" instance="LinuxVM_IN_1"
  guid="{a7b94774-db5c-4007-8707-0b9e91fd808d}" />
  <Role guid="{47a04da2-d0b7-26e2-f039-b1f1ab11337a}" name="LinuxVM"
  settleTimeSeconds="10" />
  <LoadBalancerSettings timeoutSeconds="32" waitLoadBalancerProbeCount="8">
    <Probes>
      <Probe name="LinuxVM" />
      <Probe name="03F7F19398C4358108B7ED059966EEBD" />
      <Probe name="47194D0E3AB3FCAD621CAAF698EC82D8" />
    </Probes>
  </LoadBalancerSettings>
  <OutputEndpoints>
    <Endpoint name="LinuxVM:Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp"
    type="SFS">
      <Target instance="LinuxVM_IN_0"
      endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
      <Target instance="LinuxVM_IN_1"
      endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
      <Target instance="LinuxVM_IN_2"
      endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
    </Endpoint>
  </OutputEndpoints>
  <Instances>
    <Instance id="LinuxVM_IN_1" address="10.115.38.202">
      <FaultDomains randomId="1" updateId="1" updateCount="2" />
      <InputEndpoints>
        <Endpoint name="HTTP" address="10.115.38.202:80" protocol="tcp"
        isPublic="true" loadBalancedPublicAddress="70.37.56.176:80"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="80" to="80" />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp"
        address="10.115.38.202:3389" protocol="tcp" isPublic="false"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="3389" to="3389" />
          </LocalPorts>
          <RemoteInstances>
            <RemoteInstance instance="LinuxVM_IN_0" />
            <RemoteInstance instance="LinuxVM_IN_2" />
          </RemoteInstances>
        </Endpoint>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput"
        address="10.115.38.202:20000" protocol="tcp" isPublic="true"
        loadBalancedPublicAddress="70.37.56.176:3389"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="20000" to="20000" />
          </LocalPorts>
        </Endpoint>
        <Endpoint name="SSH" address="10.115.38.202:22" protocol="tcp"
        isPublic="true" loadBalancedPublicAddress="70.37.56.176:22"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="22" to="22" />
          </LocalPorts>
        </Endpoint>
      </InputEndpoints>
    </Instance>
    <Instance id="LinuxVM_IN_0" address="10.115.58.82">
      <FaultDomains randomId="0" updateId="0" updateCount="2" />
      <InputEndpoints>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp"
        address="10.115.58.82:3389" protocol="tcp" isPublic="false"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="3389" to="3389" />
          </LocalPorts>
        </Endpoint>
      </InputEndpoints>
    </Instance>
    <Instance id="LinuxVM_IN_2" address="10.115.58.148">
      <FaultDomains randomId="0" updateId="2" updateCount="2" />
      <InputEndpoints>
        <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp"
        address="10.115.58.148:3389" protocol="tcp" isPublic="false"
        enableDirectServerReturn="false" isDirectAddress="false"
        disableStealthMode="false">
          <LocalPorts>
            <LocalPortRange from="3389" to="3389" />
          </LocalPorts>
        </Endpoint>
      </InputEndpoints>
    </Instance>
  </Instances>
</SharedConfig>
```

-----
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
