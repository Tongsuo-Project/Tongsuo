## 概述

BabaSSL是一个现代的密码学和通信安全协议的基础库。BabaSSL诞生于阿里巴巴集团和蚂蚁集团内部。BabaSSL提供如下主要的功能特性：

  * 支持[RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998)，即在TLS 1.3中使用商用密码算法
  * 支持GB/T 38636-2020 TLCP标准，即安全传输协议
  * 支持[QUIC](https://datatracker.ietf.org/doc/html/rfc9000) API
  * 支持Delegated Credentials功能，基于[draft-ietf-tls-subcerts-10](https://www.ietf.org/archive/id/draft-ietf-tls-subcerts-10.txt)
  * 支持[RFC 8879](https://datatracker.ietf.org/doc/rfc8879/)，即证书压缩
  * ……

## 教程和API文档

### 教程

除了传统的API使用说明之外，我们还提供了具体功能的使用教程，以方便用户更好的使用BabaSSL

#### 商用密码教程

* [NTLS使用手册](Tutorial/SM/ntls.md)
* [TLS1.3 + 国密(RFC8998)](Tutorial/SM/8998.md)
* [BabaSSL签发SM2证书](Tutorial/SM/sm2-gen.md)
* [BabaSSL签发SM2双证书](Tutorial/SM/dual-sm2-gen.md)

#### Delegated Credentials教程

* [Delegated Credentials代码示例](Tutorial/DC/sample.md)

### man手册

BabaSSL的API可以通过传统的man手册的方式查看

* [man1](API/man1.md)
* [man3](API/man3.md)
* [man5](API/man5.md)
* [man7](API/man7.md)

## 报告安全缺陷

我们使用蚂蚁集团的威胁报告系统，请访问如下地址进行安全缺陷的报告：

 * [https://security.alipay.com/](https://security.alipay.com)

注意：对于非安全相关的Bug，请使用Github Issues进行提交。
