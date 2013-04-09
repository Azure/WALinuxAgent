#===============================================================================
# Name: WAAgent.spec
#-------------------------------------------------------------------------------
# Purpose : RPM Spec file for Python script packaging
# Version : 1.2
# Created : April 20 2012
#===============================================================================

#%define my_release 1

Name:           WALinuxAgent
Summary:        The Windows Azure Linux Agent
Version:        1.3.2
Release:        1
License:        Apache License Version 2.0
Group:          Applications/Internet
Url:            http://go.microsoft.com/fwlink/?LinkId=250998
Source0:        WALinuxAgent-1.3.2.tar.gz
Requires:       python python-pyasn1 openssh openssl util-linux sed grep sudo iptables
Conflicts:      NetworkManager
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
Vendor:         Microsoft Corporation
Packager:       Microsoft Corporation <walinuxagent@microsoft.com>

%description
The Windows Azure Linux Agent supports the provisioning and running of Linux VMs in the Windows Azure cloud. This package should be installed on Linux disk images that are built to run in the Windows Azure environment.

%prep
%setup
find . -type f -exec sed -i 's/\r//' {} \;

%pre -p /bin/sh
if [ $1 = "1" ]
then
echo " Fresh installation of WALinuxAgent"
elif [ $1 = "2" ]
then
echo " Upgrading to higher version of WALinuxAgent"
fi

%install
mkdir -p %{buildroot}/usr/sbin
install -m 0755 waagent %{buildroot}%{_sbindir}/

%post
chmod 755 /usr/sbin/waagent
/usr/sbin/waagent -setup

%preun -p /bin/sh
if [ $1 = "0" ]
then
echo " Un-installation of WALinuxAgent"
%{_sbindir}/waagent -uninstall
fi

%postun
if [ $1 = "0" ]
then
rm -f %{_sbindir}/waagent
fi

%files
%defattr(-,root,root)
%{_sbindir}/waagent
%doc LICENSE-2.0.txt 
%doc NOTICE
%doc README
%doc Changelog

%changelog
* Fri Feb 26 2013 - walinuxagent@microsoft.com
- Updated version to 1.3.2 for release

* Fri Feb 15 2013 - walinuxagent@microsoft.com
- Updated version to 1.3.1 for release

* Fri Jan 18 2013 - walinuxagent@microsoft.com
- Updated version to 1.3 for release

* Fri Dec 07 2012 - walinuxagent@microsoft.com
- Updated version to 1.2 for release

* Fri Nov 09 2012 - walinuxagent@microsoft.com
- Added README and Changelog
- Updated version to 1.1 for release

* Thu May 17 2012 - walinuxagent@microsoft.com
- Initial WALinuxAgent packages.
