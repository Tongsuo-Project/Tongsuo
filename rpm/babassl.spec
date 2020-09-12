%define debug_package %{nil}
%define __os_install_post %{nil}

Name:           babassl
Version:8.1.3
Release:        %(echo $RELEASE)%{?dist}
Packager:       jinjiu<zuxi.wzx@alibaba-inc.com>
Summary:        OpenSSL with many awesome features (fork from openssl-1.1.1)
Group:          System Environment/Libraries
License:        BSD
Vendor:         Alibaba.Inc
Url:            git@gitlab.alipay-inc.com:afe/BabaSSL.git
Buildroot:      %{_tmppath}/%{name}-%{version}-root

%ifarch x86_64
%define arch x86_64
%else
%ifarch aarch64
%define arch aarch64
%endif
%endif

%if 0%{?alios5}
BuildRequires:  perl-5.16.3
%endif

%description
OpenSSL with many awesome features (fork from openssl-1.1.1).

%build
cd ../../../
export BUILD_ROOT=%{buildroot}
if [ -f Makefile]; then
    make clean
fi

CC=gcc ./Configure linux-%{arch} no-shared no-threads enable-tls1_3 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-keyless enable-lurk enable-evp-cipher-api-compat enable-req-status enable-status enable-crypto-mdebug-count enable-dynamic-ciphers enable-optimize-chacha enable-rsa-multi-prime-key-compat enable-session-lookup enable-session-reused-type enable-global-session-cache enable-verify-sni enable-skip-scsv enable-ntls enable-sm2 --strict-warnings --release -fPIC --prefix=/usr/local/babassl
make %{?_smp_mflags}

%install
cd ../../../
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%files
%defattr(-,root,root,-)
/usr/local/babassl

%clean
rm -rf %{buildroot}

%changelog

* Sat Nov 30 2019 jinjiu <zuxi.wzx@alibaba-inc.com>
- initial packaging - babassl
