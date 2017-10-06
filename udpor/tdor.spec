# This spec is intended to build and install on multiple distributions
# (someday). Detect the distribution we're building on.

%define ostag unknown
 
%define is_rh   %(test -e /etc/redhat-release && echo 1 || echo 0)
%define is_fc   %(test -e /etc/fedora-release && echo 1 || echo 0)

%if %{is_fc}
%define ostag %(sed -e 's/^.*release /fc/' -e 's/ .*$//' -e 's/\\./_/g' < /etc/fedora-release)
%else
%if %{is_rh}
%define ostag %(sed -e 's/^.*release /rh/' -e 's/ .*$//' -e 's/\\./_/g' < /etc/redhat-release)
%endif
%endif

%define release 1.%{ostag}

Summary:  Tdor Datagram onion transport 
Name: tdor
Version: 0.0.8
Release: %{release}
License: GPL
Group:   Applications/Network
URL:     http://www.cs.indiana.edu/~cviecco/oscode/tdor/tdor-%{version}.tar.gz 
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: openssl
Requires: libdnet >= 1.11
BuildRequires: autoconf, automake, openssl-devel,libdnet-devel


%description
Hflow is a Data coalesing engine. It 
Walleye is a web-based Honeynet data analysis interface.  Hflow is
used to populated the database, Walleye is used to examine this data.
Walleye provides cross data source views of intrusion events that
we attempt to make workflow centric.

%define bindir    /usr/bin/
%define confdir	  /etc/tdor/
%define etcdir    /etc/

%prep
%setup -n  %{name}-%{version}

%build
%configure --target=%{_target}
%{__make}

%install
rm -rf %{buildroot}
#make install 	basedir=%{buildroot}
#make install
#rm -rf $RPM_BUILD_ROOT
#mkdir -p $RPM_BUILD_ROOT%{etcdir}/hflow
#mkdir -p $RPM_BUILD_ROOT%{bindir}
#mkdir -p $RPM_BUILD_ROOT%{confdir}/misc

%{__install} -Dp -m0755 tdor	            %{buildroot}%{_bindir}/tdor
%{__install} -Dp -m0755 socksserver                %{buildroot}%{_bindir}/socksserver
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/tdor/
%{__install} -p -m0644  router_list.txt          %{buildroot}%{_sysconfdir}/tdor/

 %__mkdir -p -m 0755 $RPM_BUILD_ROOT%{_mandir}/man8
 %__install -p -m 0644 tdor.8 $RPM_BUILD_ROOT%{_mandir}/man8
 %__gzip $RPM_BUILD_ROOT%{_mandir}/man8/tdor.8

#%{__install} -m0444  hflowd.schema       %{buildroot}%{_sysconfdir}/hflow/
#%{__install} -m0444  pcre.rules          %{buildroot}%{_sysconfdir}/hflow/
#%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/hflow/misc/
#%{__install} -m0444  misc/*  		 %{buildroot}%{confdir}/misc/
#%{__install} -m0755  misc/*.pl              %{buildroot}%{confdir}/misc/
#%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/init.d/
#%{__install} -m0554 init.d/hflow %{buildroot}%{_sysconfdir}/init.d

#log and pid dirs
#%{__install} -d -m0755 %{buildroot}%{_var}/run/hflow
#%{__install} -d -m0755 %{buildroot}%{_var}/lib/hflow
#%{__install} -d -m0755 %{buildroot}%{_var}/lib/hflow/snort

%clean
#rm -rf $RPM_BUILD_ROOT
rm -rf %{buildroot}

 
%files
%defattr(-,root,root,0755)
%{bindir}/tdor
%{bindir}/socksserver
#%{_sysconfdir}/hflow/hflowd.schema 
%{_sysconfdir}/tdor/router_list.txt 
%{_mandir}/man8/tdor.8.gz


%attr(0755,root,root) %dir %{_sysconfdir}/tdor
#%attr(0755,root,root) %dir %{_sysconfdir}/hflow/misc


%post

if [ $1 -eq 1 ]; then
        #--- install
 
  #add the tdor user
  /usr/sbin/groupadd _tdor 
  /usr/sbin/useradd  -m  -c "Tdor" -d /var/log/tdor -s /dev/null -g _tdor _tdor 


fi


if [ $1 -ge 2 ]; then
        #--- upgrade, dont create new ssl key, and we dont even need to restart httpd 
echo "nothing here"
fi

%postun
if [ $1 = 0 ] ; then
        /usr/sbin/userdel _tdor 2>/dev/null
fi



