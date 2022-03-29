################################################################################

# rpmbuilder:relative-pack true

################################################################################

%global crc_check pushd ../SOURCES ; sha512sum -c %{SOURCE100} ; popd

################################################################################

%define  debug_package %{nil}

################################################################################

%define _posixroot        /
%define _root             /root
%define _bin              /bin
%define _sbin             /sbin
%define _srv              /srv
%define _home             /home
%define _opt              /opt
%define _lib32            %{_posixroot}lib
%define _lib64            %{_posixroot}lib64
%define _libdir32         %{_prefix}%{_lib32}
%define _libdir64         %{_prefix}%{_lib64}
%define _logdir           %{_localstatedir}/log
%define _rundir           %{_localstatedir}/run
%define _lockdir          %{_localstatedir}/lock/subsys
%define _cachedir         %{_localstatedir}/cache
%define _spooldir         %{_localstatedir}/spool
%define _crondir          %{_sysconfdir}/cron.d
%define _loc_prefix       %{_prefix}/local
%define _loc_exec_prefix  %{_loc_prefix}
%define _loc_bindir       %{_loc_exec_prefix}/bin
%define _loc_libdir       %{_loc_exec_prefix}/%{_lib}
%define _loc_libdir32     %{_loc_exec_prefix}/%{_lib32}
%define _loc_libdir64     %{_loc_exec_prefix}/%{_lib64}
%define _loc_libexecdir   %{_loc_exec_prefix}/libexec
%define _loc_sbindir      %{_loc_exec_prefix}/sbin
%define _loc_bindir       %{_loc_exec_prefix}/bin
%define _loc_datarootdir  %{_loc_prefix}/share
%define _loc_includedir   %{_loc_prefix}/include
%define _loc_mandir       %{_loc_datarootdir}/man
%define _rpmstatedir      %{_sharedstatedir}/rpm-state
%define _pkgconfigdir     %{_libdir}/pkgconfig

################################################################################

Summary:         Pretty awesome command-line client for public SSLLabs API
Name:            sslcli
Version:         2.7.1
Release:         0%{?dist}
Group:           Applications/System
License:         Apache License, Version 2.0
URL:             https://kaos.sh/sslcli

Source0:         https://source.kaos.st/%{name}/%{name}-%{version}.tar.bz2

Source100:       checksum.sha512

BuildRoot:       %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:   golang >= 1.17

Provides:        %{name} = %{version}-%{release}

################################################################################

%description
Pretty awesome command-line client for public SSLLabs API.

################################################################################

%prep
%{crc_check}

%setup -q

%build
export GOPATH=$(pwd)
go build src/github.com/essentialkaos/sslcli/%{name}.go

%install
rm -rf %{buildroot}

install -dm 755 %{buildroot}%{_bindir}
install -dm 755 %{buildroot}%{_mandir}/man1

install -pm 755 %{name} %{buildroot}%{_bindir}/

./%{name} --generate-man > %{buildroot}%{_mandir}/man1/%{name}.1

%clean
rm -rf %{buildroot}

%post
if [[ -d %{_sysconfdir}/bash_completion.d ]] ; then
  %{name} --completion=bash 1> %{_sysconfdir}/bash_completion.d/%{name} 2>/dev/null
fi

if [[ -d %{_datarootdir}/fish/vendor_completions.d ]] ; then
  %{name} --completion=fish 1> %{_datarootdir}/fish/vendor_completions.d/%{name}.fish 2>/dev/null
fi

if [[ -d %{_datadir}/zsh/site-functions ]] ; then
  %{name} --completion=zsh 1> %{_datadir}/zsh/site-functions/_%{name} 2>/dev/null
fi

%postun
if [[ $1 == 0 ]] ; then
  if [[ -f %{_sysconfdir}/bash_completion.d/%{name} ]] ; then
    rm -f %{_sysconfdir}/bash_completion.d/%{name} &>/dev/null || :
  fi

  if [[ -f %{_datarootdir}/fish/vendor_completions.d/%{name}.fish ]] ; then
    rm -f %{_datarootdir}/fish/vendor_completions.d/%{name}.fish &>/dev/null || :
  fi

  if [[ -f %{_datadir}/zsh/site-functions/_%{name} ]] ; then
    rm -f %{_datadir}/zsh/site-functions/_%{name} &>/dev/null || :
  fi
fi

################################################################################

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_mandir}/man1/%{name}.1.*
%{_bindir}/%{name}

################################################################################

%changelog
* Tue Mar 29 2022 Anton Novojilov <andy@essentialkaos.com> - 2,7,1-0
- Removed pkg.re usage
- Added module info
- Added Dependabot configuration

* Wed Jan 13 2021 Anton Novojilov <andy@essentialkaos.com> - 2.7.0-0
- sslscan package updated to v13

* Wed May 06 2020 Anton Novojilov <andy@essentialkaos.com> - 2.6.0-0
- Fixed panic if HPKPPolicy is empty
- ek package updated to v12

* Fri Jan 03 2020 Anton Novojilov <andy@essentialkaos.com> - 2.5.0-0
- Updated for compatibility with the latest version of SSLLabs API

* Sat Oct 19 2019 Anton Novojilov <andy@essentialkaos.com> - 2.4.1-0
- ek package updated to the latest version

* Tue Jul 09 2019 Anton Novojilov <andy@essentialkaos.com> - 2.4.0-0
- Added '--max-left/-M' for checking certificate expiry date
- Added completions for bash, fish and zsh
- Minor improvements

* Mon Jun 03 2019 Anton Novojilov <andy@essentialkaos.com> - 2.3.1-0
- Updated for compatibility with the latest version of SSLLabs API

* Tue Apr 30 2019 Anton Novojilov <andy@essentialkaos.com> - 2.3.0-0
- Added Zombie Poodle vulnerability info
- Added Golden Doodle vulnerability info
- Added Sleeping Poodle vulnerability info
- Added OpenSSL 0-Length vulnerability info

* Tue Mar 19 2019 Anton Novojilov <andy@essentialkaos.com> - 2.2.0-0
- Added info about 0-RTT support
- Minor UI fixes

* Mon Feb 11 2019 Anton Novojilov <andy@essentialkaos.com> - 2.1.0-0
- Improved DROWN check status output

* Sat Feb 09 2019 Anton Novojilov <andy@essentialkaos.com> - 2.0.1-0
- Fixed compatibility with the latest version of ek package

* Tue Jan 29 2019 Anton Novojilov <andy@essentialkaos.com> - 2.0.0-0
- Improved UI
- Info about HTTP transactions
- Info about TLS 1.3 cipher suites
- Info about Bleichenbacher vulnerability
- Info about Ticketbleed vulnerability
- Info about root trust stores
- Info about Static Public Key Pinning
- Info about ECDH public server param reuse
- Info about required SNI
- Info about supported named groups
- Migrated to sslscan.v10
- Minor improvements

* Sun Nov 18 2018 Anton Novojilov <andy@essentialkaos.com> - 1.9.0-0
- ek package updated to v10
- sslscan package updated to v9

* Tue Mar 06 2018 Anton Novojilov <andy@essentialkaos.com> - 1.8.0-0
- ek package updated to latest stable release
- sslscan package updated to v8
- UI fixes

* Fri Dec 22 2017 Anton Novojilov <andy@essentialkaos.com> - 1.7.0-0
- Updated compatibility with latest version of sslscan package

* Sat Dec 02 2017 Anton Novojilov <andy@essentialkaos.com> - 1.6.1-0
- Updated compatibility with latest version of ek package

* Thu May 25 2017 Anton Novojilov <andy@essentialkaos.com> - 1.6.0-0
- ek package updated to v9
- sslscan package updated to v7

* Sun Apr 16 2017 Anton Novojilov <andy@essentialkaos.com> - 1.5.0-0
- ek package updated to v8
- sslscan package updated to v6

* Sat Apr 08 2017 Anton Novojilov <andy@essentialkaos.com> - 1.4.1-0
- UI improvements

* Fri Mar 10 2017 Anton Novojilov <andy@essentialkaos.com> - 1.4.0-0
- ek package updated to v7
- sslscan package updated to v5

* Fri Oct 28 2016 Anton Novojilov <andy@essentialkaos.com> - 1.3.0-0
- sslscan updated to v4

* Sat Oct 15 2016 Anton Novojilov <andy@essentialkaos.com> - 1.2.0-0
- Numerical grade values in all output formats
- YAML output support
- API 1.24.0 compatibility
- less-friendly server message output

* Wed Oct 12 2016 Anton Novojilov <andy@essentialkaos.com> - 1.1.1-0
- Fixed bug with unhandled API error

* Tue Oct 11 2016 Anton Novojilov <andy@essentialkaos.com> - 1.1.0-0
- EK package updated to v5
- SSLScan package udated to v2

* Fri Sep 23 2016 Anton Novojilov <andy@essentialkaos.com> - 1.0.2-0
- Minor UI improvements

* Thu Oct 08 2015 Anton Novojilov <andy@essentialkaos.com> - 1.0.0-0
- Initial release
