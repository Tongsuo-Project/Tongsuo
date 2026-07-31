
 Tongsuo CHANGES
 _______________

 Changes between 8.5.0-pre1 and 8.5.0-pre2 [3 Aug 2026]

  *) 修复若干 CVE 和安全问题

  *) 修复若干编译问题

  *) 提供 BoringSSL-style QUIC 接口

  *) 提供白盒 SM4 功能

 Changes between 8.4.0 and 8.5.0-pre1 [23 Mar 2026]

  *) 修复 CVE 若干

  *) 优化 AES-GCM、SM4-GCM、HMAC、CMAC、RSA 等密码学方案以及 TLS 协议的性能，相较 8.4.0 最多可翻倍

  *) TLS 连接的安全等级默认设置为 2，禁用过低的协议版本（如 TLS1.1 ）和安全强度低于 112bit 的密码原语

  *) 支持 PQC 算法 ML-KEM、ML-DSA 和 SLH-DSA，支持 PQC 密钥协商机制 curveSM2MLKEM768、X25519MLKEM768 等

  *) 实现 QUIC 协议（RFC9000）

  *) 实现 TCP Fast Open（RFC7413）

  *) 实现 HPKE（RFC9180）

  *) 实现 AES-GCM-SIV（RFC8452）

  *) 支持在 TLS 中使用 raw public key（RFC7250）

  *) 支持使用 brotli 和 zstd 进行证书压缩（RFC8879）

  *) 支持在 TLS1.3 ClientHello 中包含多个 keyshare

  *) 添加 TLS round-trip 时间测量功能

  *) SMTC Provider 适配蚂蚁密码卡（atf_slibce）

  *) 增加 SDF 框架和部分功能接口

  *) 随机数熵源增加 rtcode、rtmem 和 rtsock

  *) speed 支持测试 SM2 密钥对生成和 SM4 密钥对生成

  *) 增加 TSAPI，支持常见密码学算法

  *) 增加 SM2 两方门限解密/签名算法

  *) 增加商用密码检测和认证 Provider，包括身份认证、完整性验证、算法自测试、随机数自检、
     熵源健康测试；增加 mod 应用，包括生成 SMTC 配置、自测试功能

  *) 基础代码迁移到 OpenSSL 3.5.4

  Changes between 8.3.0 and 8.4.0 [15 Dec 2023]

  *) 修复多个安全漏洞

  *) 支持零知识证明算法-NIZKPoK 和实现 ZKP 范围证明工具

  *) 实现基于64位平台架构的SM2算法性能优化

  *) 实现基于SM2曲线参数特化的快速模约减和快速模逆元算法

  *) 支持零知识证明算法-bulletproofs (r1cs)

  *) ZUC 算法优化以及 speed 支持 ZUC 算法

  *) s_server支持配置多证书测试TLCP SNI功能

  *) SSL_connection_is_ntls改成使用预读方式判断是否为NTLS

  *) 支持零知识证明算法-bulletproofs (range proof)

  *) Paillier 支持硬件加速

  *) BIGNUM 运算支持 method 机制

  *) 支持半同态加密算法 Twisted-EC-ElGamal

  *) 支持半同态加密算法 EC-ElGamal 命令行

  *) 支持半同态加密算法-Paillier

  *) 删除多种不常用算法

  *) 删除对VMS系统的支持

  *) 删除多种文档相关、工具类代码

  *) 支持新特性 - 添加导出符号前缀

  *) 删除PA-RISC架构代码

  *) 删除SPARC架构代码

  *) 支持椭圆曲线（EC）点计算硬件加速 API

  *) 修复2处SM2签名算法的实现bug [0x9527-zhou]

  *) 基础代码迁移到OpenSSL 3.0.2

 以下是BabaSSL的CHANGES:

 Changes between 8.2.0 and 8.3.0 [28 Feb 2022]

  *) Fix CVE-2021-4160

  *) Support wrap mode in `openssl enc` command

  *) ASYNC: Fixes for nested job creation

  *) Support TLS certificate compression (RFC 8879)

  *) A bundle of upstream patches are backported [hustliyilin]

  *) Support NTLS session ticket

  *) Support integrity algorithm 128-EIA3

  *) Support NTLS client authentication

  *) Remove ARIA cipher

  *) Support software random generator in compliance with Chinese SCA

  *) Support PHE algorithm EC-Elgamal

  *) Support RSA_SM4 cipher suites for NTLS

  *) SM3 and SM4 hardware acceleration on aarch64

  *) SM4 optimization for non-asm mode

 Changes between 8.1.3 and 8.2.0 [19 May 2021]

  *) Support NTLS(formal GM double cert) handshake processing, GB/T 38636-2020 TLCP

  *) Support delegated credential

  *) Update BoringSSL QUIC API

  *) Fix CVE-2021-3449

  *) Fix CVE-2021-23840 and CVE-2021-23841

 Changes with 8.1.3 [15 Jan 2021]

  *) Support more QUIC related APIs

  *) Fix CVE-2020-1971

  *) Fix CVE-2020-1967

  *) Give a default sm2-id for sm2 sign process which not set sm-id

  *) Support BoringSSL QUIC API

  *) Fix up problems of CVE-2019-1551

  *) Support TLS1.3-GM cipher suite, see https://datatracker.ietf.org/doc/html/rfc8998 for more information

  *) Support global session cache, asynchronous session lookup

  *) Support SM2 cert sign, SM2 speed testing for babassl/apps

  *) Support dynamic cipher, make EVP api compatible with lua ffi

  *) Fork from OpenSSL version 1.1.1d