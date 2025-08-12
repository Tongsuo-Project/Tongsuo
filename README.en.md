OpenAtom Tongsuo
=========================

[![tongsuo logo]][www.tongsuo.net]

[![github actions ci badge]][github actions ci]
[![Coverage Status](https://coveralls.io/repos/github/Tongsuo-Project/Tongsuo/badge.svg?branch=master)](https://coveralls.io/github/Tongsuo-Project/Tongsuo?branch=master)
![GitHub Release][github release]
[![GitHub Downloads (all assets, all releases)][github downloads]](https://github.com/Tongsuo-Project/Tongsuo/releases)

Tongsuo is an open-source foundational cryptographic library that provides modern cryptographic algorithms and secure communication protocols. It offers underlying cryptographic capabilities for various business scenarios including storage, networking, key management, and privacy computing, ensuring confidentiality, integrity, and authenticity of data during transmission, usage, and storage, providing privacy and security protection throughout the data lifecycle.

Tongsuo has obtained the Commercial Cryptographic Product Certification issued by the [Commercial Cryptography Testing and Certification Center](https://www.scctc.org.cn/), helping users meet the requirements of China's commercial cryptographic technology compliance more rigorously in the process of national cryptographic transformation, cryptographic evaluation, and classified protection. The original qualification documents can be downloaded [here](https://www.yuque.com/tsdoc/misc/st247r05s8b5dtct).

<div align="center">    
 <img src="https://github.com/Tongsuo-Project/Tongsuo/blob/master/validation-android.png" width=50% height=50% align=center />
</div>


Features
=========================

Tongsuo provides the following key features:

  * Technical Compliance Capabilities
    * Complies with GM/T 0028 "Security requirements for cryptographic modules" - "Software Cryptographic Module Security Level 1" qualification
    * Complies with GM/T 0005-2021 "Randomness test specification"
  * Zero-Knowledge Proof (ZKP)
    * Bulletproofs range
    * [Bulletproofs R1CS](https://www.yuque.com/tsdoc/ts/bulletproofs)
  * Cryptographic Algorithms
    * Chinese commercial cryptographic algorithms: SM2, SM3, SM4, [ZUC](https://www.yuque.com/tsdoc/ts/copzp3), etc.
    * International mainstream algorithms: ECDSA, RSA, AES, SHA, etc.
    * Homomorphic encryption algorithms: [EC-ElGamal](https://www.yuque.com/tsdoc/misc/ec-elgamal), [Paillier](https://www.yuque.com/tsdoc/misc/rdibad), etc.
    * Post-quantum cryptography\*: Kyber, Dilithium, etc.
  * Secure Communication Protocols
    * Supports GB/T 38636-2020 TLCP standard, i.e., [dual-certificate national cryptographic](https://www.yuque.com/tsdoc/ts/hedgqf) communication protocol
    * Supports [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998), i.e., TLS 1.3 + [national cryptographic single certificate](https://www.yuque.com/tsdoc/ts/grur3x)
    * Supports [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) API
    * Supports [Delegated Credentials](https://www.yuque.com/tsdoc/ts/leubbg) functionality, based on [draft-ietf-tls-subcerts-10](https://www.ietf.org/archive/id/draft-ietf-tls-subcerts-10.txt)
    * Supports [TLS certificate compression](https://www.yuque.com/tsdoc/ts/df5pyi)
    * Supports compact TLS protocol\*

Note: \* indicates work in progress

Typical Applications
=======

Open Source Applications

* [Angie](https://angie.software/en/), Angie is a new web server that can replace NGINX. We highly recommend Tongsuo users to choose Angie first (We highly recommend you to replace NGINX with Angie to enable Tongsuo's functionality)
* Apache APISIX
* Tengine
* [g3proxy](https://github.com/bytedance/g3/tree/master/g3proxy), forward proxy & basic reverse proxy
* [g3bench](https://github.com/bytedance/g3/tree/master/g3bench), stress testing for HTTPS/H2/TLS handshake, etc.

Commercial Applications

* Alipay App
* OceanBase Database
* Alibaba Cloud
* iTrusChina


Compilation and Installation
=========

Generally, the typical compilation and installation process is as follows:

~~~
./config --prefix=/path/to/install/dir
make
make install
~~~

For Windows user, you need:

~~~
perl Configure enable-ntls
nmake
nmake install
~~~

This will install Tongsuo's header files, library files, and Tongsuo binary programs. If you need to compile Tongsuo in a separate build directory to keep the source code repository clean, you can:

~~~
cd tongsuo-build
/path/to/Tongsuo/source/config --prefix=/path/to/dest
make
make install
~~~

Currently, Tongsuo supports the following operating systems: various Linux distributions, macOS, Android, iOS, and Windows. On these operating systems, you need to prepare the corresponding environment in advance:

* make
* Perl 5, and the Text::Template module
* C compiler
* C library

Tongsuo has few dependencies on third-party libraries, but currently still has a large dependency on Perl.

If you want to run automated test cases, you need:

~~~
make test
~~~

During installation, you can choose to install only library files:

~~~
make install_runtime_libs
~~~

If you also need to install header files for developing applications based on Tongsuo, you can:

~~~
make install_dev
~~~

You can also install only Tongsuo binary programs and their dependent Tongsuo library files:

~~~
make install_programs
~~~

Tongsuo's Configure script provides a large number of options for enabling and disabling various features. Generally speaking, use `enable-xxx` to enable a feature, and use `no-xxx` to disable a feature. For example, `enable-ntls` enables TLCP, while `no-rsa` disables compilation of the RSA algorithm.

Documentation
=========================

Tongsuo's related documentation is organized on the [Tongsuo Documentation Website](https://www.tongsuo.net/docs).

Communication and Collaboration
=========================

Tongsuo uses DingTalk groups for user Q&A and communication. DingTalk group number: 44810299

Welcome to follow the Tongsuo WeChat official account to get the latest Tongsuo updates:

![tongsuo public qr](tongsuo-public-qr.jpg)

Declaration
=========================

Tongsuo is an open-source project incubated and operated by the OpenAtom Foundation.

<img src="atom-logo.svg" alt="OpenAtom Foundation" width=50% height=50% />

Reporting Security Vulnerabilities
=========================

Tongsuo currently uses Ant Group's threat collection system. Please visit the following address to report security vulnerabilities:

 * [https://security.alipay.com/](https://security.alipay.com/)

Note: For non-security-related bugs, please use GitHub Issues for submission.

<!-- Links  -->

[www.tongsuo.net]:
    <https://www.tongsuo.net>
    "Tongsuo Homepage"

<!-- Logos and Badges -->

[tongsuo logo]:
    tongsuo.png
    "Tongsuo Logo"

[github actions ci badge]:
    <https://github.com/Tongsuo-Project/Tongsuo/workflows/GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/Tongsuo-Project/Tongsuo/actions?query=workflow%3A%22GitHub+CI%22>
    "GitHub Actions CI"

[github release]:
    <https://img.shields.io/github/v/release/Tongsuo-Project/Tongsuo>
    "GitHub Release"

[github downloads]:
    <https://img.shields.io/github/downloads/Tongsuo-Project/Tongsuo/total?link=https%3A%2F%2Fgithub.com%2FTongsuo-Project%2FTongsuo%2Freleases>
    "GitHub Downloads"