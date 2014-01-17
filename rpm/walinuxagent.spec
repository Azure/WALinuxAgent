#===============================================================================
# Name: walinuxagent.spec
#-------------------------------------------------------------------------------
# Purpose : RPM Spec file for Python script packaging
# Version : 2.0.0
# Created : April 20 2012
#===============================================================================

Name:           WALinuxAgent
Summary:        The Windows Azure Linux Agent
Version:        2.0.3
Release:        1
License:        Apache License Version 2.0
Group:          System/Daemons
Url:            http://go.microsoft.com/fwlink/?LinkId=250998
Source0:        WALinuxAgent-2.0.3.tar.gz
Requires:       python python-pyasn1 openssh openssl util-linux sed grep sudo iptables
Conflicts:      NetworkManager
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
Vendor:         Microsoft Corporation
Packager:       Microsoft Corporation <walinuxagent@microsoft.com>

%description
The Windows Azure Linux Agent supports the provisioning and running of Linux
VMs in the Windows Azure cloud. This package should be installed on Linux disk
images that are built to run in the Windows Azure environment.

%prep
%setup -q
find . -type f -exec sed -i 's/\r//' {} +
find . -type f -exec chmod 0644 {} +

%pre -p /bin/sh

%build
# Nothing to do

%install
python setup.py install --prefix=%{_prefix} --lnx-distro='redhat' --init-system='sysV' --root=%{buildroot}
mkdir -p  %{buildroot}/%{_localstatedir}/log
touch %{buildroot}/%{_localstatedir}/log/waagent.log

%post
/sbin/chkconfig --add waagent

%preun -p /bin/sh
if [ $1 = 0 ]; then
	/sbin/service waagent stop >/dev/null 2>&1
	/sbin/chkconfig --del waagent
fi

%postun -p /bin/sh
if [ "$1" -ge "1" ]; then
	/sbin/service waagent restart >/dev/null 2>&1 || :
fi


%files
%attr(0755,root,root) %{_initddir}/waagent
%defattr(0644,root,root,0755)
%doc Changelog LICENSE-2.0.txt NOTICE README
%attr(0755,root,root) %{_sbindir}/waagent
%config(noreplace) %{_sysconfdir}/logrotate.d/waagent
%config %{_sysconfdir}/waagent.conf
%ghost %{_localstatedir}/log/waagent.log


%changelog
* Thu Jan 16 2014 - walinuxagent@microsoft.com
- Updated version to 2.0.3 for release

* Wed Dec 18 2013 - walinuxagent@microsoft.com
- Updated version to 2.0.2 for release

* Tue Nov 05 2013 - walinuxagent@microsoft.com
- Updated version to 2.0.1 for release

* Fri Sep 20 2013 - walinuxagent@microsoft.com
- Updated version to 2.0.0 for release

* Thu Aug 23 2013 - walinuxagent@microsoft.com
- Updated version to 1.4.0 for release

* Thu May 30 2013 - walinuxagent@microsoft.com
- Updated version to 1.3.3 for release

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
