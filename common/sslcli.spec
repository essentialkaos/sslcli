###############################################################################

# rpmbuilder:relative-pack true

###############################################################################

%define  debug_package %{nil}

###############################################################################

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

###############################################################################

Summary:         Pretty awesome command-line client for public SSLLabs API
Name:            sslcli
Version:         1.6.1
Release:         0%{?dist}
Group:           Applications/System
License:         EKOL
URL:             http://essentialkaos.com

Source0:         https://source.kaos.io/%{name}/%{name}-%{version}.tar.bz2

BuildRoot:       %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:   golang >= 1.8

Provides:        %{name} = %{version}-%{release}

###############################################################################

%description
Pretty awesome command-line client for public SSLLabs API.

###############################################################################

%prep
%setup -q

%build
export GOPATH=$(pwd)
go build src/github.com/essentialkaos/sslcli/%{name}.go

%install
rm -rf %{buildroot}

install -dm 755 %{buildroot}%{_bindir}

install -pm 755 %{name} %{buildroot}%{_bindir}/

%clean
rm -rf %{buildroot}

###############################################################################

%files
%defattr(-,root,root,-)
%doc LICENSE.EN LICENSE.RU
%{_bindir}/%{name}

###############################################################################

%changelog
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
