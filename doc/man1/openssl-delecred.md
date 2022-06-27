# openssl-delecred用户手册

delecred用于签发或输出delegate credential。

## 选项和参数

-help                  输出帮助信息
-in infile             设置输入的DC文件
-out outfile           设置输出的DC文件
-new                   创建一个新的delegated credential
-dc_key val            设置delegated credential的私钥
-parent_cert val       设置签发dc的证书
-parent_key val        设置签发dc的私钥
-sec +int              设置dc的有效时长，默认值和最大值都是604800秒
-expect_verify_md val  设置期望的验签算法的哈希算法
-*                     设置签名的哈希算法
-client                表示DC用于客户端
-server                表示DC用于服务端
-text                  以文本格式输出DC
-noout                 不输出DC原始内容

## 示例

输出delegated credential的详细内容：

```shell
openssl delecred -in /path/to/dc -text -noout
```

使用服务端证书和私钥签发一个服务端的DC：

```shell
openssl delecred -new -server -expect_verify_md sha256 -sha256 \
    -parent_cert /path/to/server/cert -parent_key /path/to/server/key \
    -dc_key /path/to/server/dc.key -out /path/to/server/dc
```

使用客户端证书和私钥签发一个客户端的DC:

```shell
openssl delecred -new -client -expect_verify_md sha256 -sha256 \
    -parent_cert /path/to/client/cert -parent_key /path/to/client/key \
    -dc_key /path/to/client/dc.key -out /path/to/client/dc
```

## 版权

版权归Tongsuo项目作者所有。

该文件使用Apache 2.0许可证，请在遵守许可证的前提下使用该文件，可通过以下链接获取
[许可证副本](https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt)。
