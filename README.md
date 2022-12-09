概述
=========================

铜锁/Tongsuo（原BabaSSL）是一个提供现代密码学算法和安全通信协议的开源基础密码库，为存储、网络、密钥管理、隐私计算等诸多业务场景提供底层的密码学基础能力，实现数据在传输、使用、存储等过程中的私密性、完整性和可认证性，为数据生命周期中的隐私和安全提供保护能力。

铜锁获得了国家密码管理局商用密码检测中心颁发的商用密码产品认证证书，助力用户在国密改造、密评、等保等过程中，更加严谨地满足我国商用密码技术合规的要求。可在[此处](https://www.yuque.com/tsdoc/misc/st247r05s8b5dtct)下载资质原始文件。

<img src="./validation-android.png" width=50% height=50% />


特性
=========================

铜锁提供如下主要的功能特性：

  * 技术合规能力
    * 符合GM/T 0028《密码模块安全技术要求》的”软件密码模块安全一级“资质
  * 密码学算法
    * 中国商用密码算法：SM2、SM3、SM4、[祖冲之](https://www.yuque.com/tsdoc/ts/copzp3)等
    * 国际主流算法：ECDSA、RSA、AES、SHA等
    * 同态加密算法：[EC-ElGamal](https://www.yuque.com/tsdoc/misc/ec-elgamal)、[Paillier](https://www.yuque.com/tsdoc/misc/rdibad)等
    * 后量子密码学*：LAC、NTRU、Saber、Dilithium等
  * 安全通信协议
    * 支持GB/T 38636-2020 TLCP标准，即[双证书国密](https://www.yuque.com/tsdoc/ts/hedgqf)通信协议
    * 支持[RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998)，即TLS 1.3 +[国密单证书](https://www.yuque.com/tsdoc/ts/grur3x)
    * 支持[QUIC](https://datatracker.ietf.org/doc/html/rfc9000) API
    * 支持[Delegated Credentials](https://www.yuque.com/tsdoc/ts/leubbg)功能，基于[draft-ietf-tls-subcerts-10](https://www.ietf.org/archive/id/draft-ietf-tls-subcerts-10.txt)
    * 支持[TLS证书压缩](https://www.yuque.com/tsdoc/ts/df5pyi)
    * 支持紧凑TLS协议*

注：*号表示正在支持中

编译和安装
=========
一般来说，典型的编译和安装过程如下：

~~~
./config --prefix=/path/to/install/dir
make
make install
~~~

如果是Windows，则需要：

~~~
perl config
nmake
nmake install
~~~

以上将会安装铜锁的头文件、library文件和铜锁二进制程序。如果需要在独立的build目录中编译铜锁以保证源代码仓库的整洁，则可以：

~~~
cd tongsuo-build
/path/to/Tongsuo/source/config --prefix=/path/to/dest
make
make install
~~~

目前铜锁支持的操作系统有：各种Linux发行版、macOS、Android、iOS和Windows。在这些操作系统上，还需要事先准备好对应的环境：

* make
* Perl 5，以及Text::Template模块
* C编译器
* C库

铜锁对第三方库的依赖很少，但是目前依然对Perl依赖较大。

如果希望执行自动化测试用例，则需：

~~~
make test
~~~

在安装的时候，可以选择只安装library文件：

~~~
make install_runtime_libs
~~~

如果还需要安装头文件以便于基于铜锁开发应用程序，则可以：

~~~
make install_dev
~~~

也可以只安装铜锁二进制程序和其依赖的铜锁library文件：

~~~
make install_programs
~~~

铜锁的Configure脚本提供了大量的用于开关各种特性的选项。一般来讲，使用`enable-xxx`做为对某个特性的开启，而使用`no-xxx`来关闭某个特性。例如，`enable-ntls`即开启TLCP，而`no-rsa`则是不编译RSA算法。

文档
=========================

铜锁的相关文档组织在 [铜锁文档网站](https://yuque.com/tsdoc) 上。

交流群
=========================

铜锁使用钉钉群进行用户答疑和交流，欢迎扫码入群（也可直接搜索群号：44810299）：
<img src=
"https://github.com/Tongsuo-Project/Tongsuo/blob/master/tongsuo-dingtalk.jpg"
width=50% height=50% />

报告安全缺陷
=========================

铜锁目前使用蚂蚁集团的威胁搜集系统，请访问如下地址进行安全缺陷的报告：

 * [https://security.alipay.com/](https://security.alipay.com/)

注意：对于非安全相关的Bug，请使用GitHub的Issues进行提交。
