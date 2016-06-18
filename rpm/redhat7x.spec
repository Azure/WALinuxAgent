#===============================================================================
# Name: redhat7x.spec
#-------------------------------------------------------------------------------
# Purpose : RPM Spec file for Python script packaging
# Version : 2.0.15
# Created : July 8 2015
#===============================================================================

Name:           WALinuxAgent
Summary:        The Azure Linux Agent
Version:        %{_agentversion}
Release:        1
License:        Apache License Version 2.0
Group:          System/Daemons
Url:            http://go.microsoft.com/fwlink/?LinkId=250998
Source0:        WALinuxAgent-%{_agentversion}.tar.gz
Requires:       python python-pyasn1 openssh openssl util-linux sed grep sudo iptables parted
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
Vendor:         Microsoft Corporation
Packager:       Microsoft Corporation <walinuxagent@microsoft.com>

%description
The Windows Azure Linux Agent supports the provisioning and running of Linux
VMs in the Microsoft Azure cloud. This package should be installed on Linux disk
images that are built to run in the Microsoft Azure environment.

%prep
%setup -q
find . -type f -exec sed -i 's/\r//' {} +
find . -type f -exec chmod 0644 {} +

%pre -p /bin/sh

%build
# Nothing to do

%install
python setup.py install --prefix=%{_prefix} --lnx-distro='redhat' --init-system='systemd' --root=%{buildroot} 
mkdir -p  %{buildroot}/%{_localstatedir}/log
mkdir -p -m 0700 %{buildroot}/%{_sharedstatedir}/waagent
touch %{buildroot}/%{_localstatedir}/log/waagent.log

%post
systemctl enable waagent

%preun -p /bin/sh
if [ $1 = 0 ]; then
	systemctl stop waagent>/dev/null 2>&1
    systemctl disable waagent
fi

%postun -p /bin/sh
if [ "$1" -ge "1" ]; then
	systemctl restart waagent>/dev/null 2>&1 || :
fi


%files
%attr(0755,root,root) %{_usr}/lib/systemd/system/waagent.service
%attr(0644,root,root) %{_sysconfdir}/udev/rules.d/99-azure-product-uuid.rules
%attr(0644,root,root) %{_sysconfdir}/udev/rules.d/66-azure-storage.rules
%defattr(0644,root,root,0755)
%doc Changelog LICENSE-2.0.txt NOTICE README
%attr(0755,root,root) %{_sbindir}/waagent
%config(noreplace) %{_sysconfdir}/logrotate.d/waagent
%config %{_sysconfdir}/waagent.conf
%ghost %{_localstatedir}/log/waagent.log
%dir %attr(0700, root, root) %{_sharedstatedir}/waagent


%changelog
* Wed Jul 08 2015 - walinuxagent@microsoft.com
- Create a sperate spec for redhat7+

