# Delegated Credentials接口文档

## 接口

```c

#include <openssl/x509.h>

# ifndef OPENSSL_NO_DELEGATED_CREDENTIAL
# define DC_FILETYPE_RAW       0

DELEGATED_CREDENTIAL *DC_new(void);
DELEGATED_CREDENTIAL *DC_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
DELEGATED_CREDENTIAL *DC_new_from_raw_byte(const unsigned char *byte,
                                           size_t len);
DELEGATED_CREDENTIAL *DC_new_from_raw_byte_ex(const unsigned char *byte,
                                              size_t len,
                                              OSSL_LIB_CTX *libctx,
                                              const char *propq);
void DC_free(DELEGATED_CREDENTIAL *dc);
int DC_check_valid(X509 *parent_cert, DELEGATED_CREDENTIAL *dc);
int DC_check_time_valid(X509 *parent_cert, DELEGATED_CREDENTIAL *dc);
int DC_check_parent_cert_valid(X509 *parent_cert);
unsigned long DC_get_valid_time(DELEGATED_CREDENTIAL *dc);
unsigned int DC_get_expected_cert_verify_algorithm(DELEGATED_CREDENTIAL *dc);
size_t DC_get_dc_publickey_raw_len(DELEGATED_CREDENTIAL *dc);
unsigned char *DC_get0_dc_publickey_raw(DELEGATED_CREDENTIAL *dc);
unsigned int DC_get_signature_sign_algorithm(DELEGATED_CREDENTIAL *dc);
size_t DC_get_dc_signature_len(DELEGATED_CREDENTIAL *dc);
unsigned char *DC_get0_dc_signature(DELEGATED_CREDENTIAL *dc);
EVP_PKEY *DC_get0_publickey(DELEGATED_CREDENTIAL *dc);
unsigned char *DC_get0_raw_byte(DELEGATED_CREDENTIAL *dc);
size_t DC_get_raw_byte_len(DELEGATED_CREDENTIAL *dc);
int DC_set_valid_time(DELEGATED_CREDENTIAL *dc, unsigned long valid_time);
int DC_set_expected_cert_verify_algorithm(DELEGATED_CREDENTIAL *dc,
unsigned int alg);
int DC_set_dc_publickey_len(DELEGATED_CREDENTIAL *dc, size_t len);
int DC_set0_dc_publickey(DELEGATED_CREDENTIAL *dc, unsigned char *pub_key);
int DC_set_signature_sign_algorithm(DELEGATED_CREDENTIAL *dc, unsigned int alg);
int DC_set_dc_signature_len(DELEGATED_CREDENTIAL *dc, size_t len);
int DC_set0_dc_signature(DELEGATED_CREDENTIAL *dc, unsigned char *sig);
int DC_set0_raw_byte(DELEGATED_CREDENTIAL *dc, unsigned char *byte, size_t len);
int DC_set1_raw_byte(DELEGATED_CREDENTIAL *dc, const unsigned char *byte,
size_t len);
int DC_set0_publickey(DELEGATED_CREDENTIAL *dc, EVP_PKEY *pkey);


int DC_check_private_key(DELEGATED_CREDENTIAL *dc, EVP_PKEY *pkey);

int DC_up_ref(DELEGATED_CREDENTIAL *dc);
DELEGATED_CREDENTIAL *DC_load_from_file(const char *file);
DELEGATED_CREDENTIAL *DC_load_from_file_ex(const char *file,
                                           OSSL_LIB_CTX *libctx,
                                           const char *propq);
# endif

#include <openssl/ssl.h>

# ifndef OPENSSL_NO_DELEGATED_CREDENTIAL
#  define DC_REQ_HAS_BEEN_SEND_TO_PEER          0x01
#  define DC_HAS_BEEN_USED_FOR_VERIFY_PEER      0x02
#  define DC_HAS_BEEN_USED_FOR_SIGN             0x04

void SSL_CTX_enable_verify_peer_by_dc(SSL_CTX *ctx);
void SSL_CTX_disable_verify_peer_by_dc(SSL_CTX *ctx);
void SSL_enable_verify_peer_by_dc(SSL *s);
void SSL_disable_verify_peer_by_dc(SSL *s);
void SSL_CTX_enable_sign_by_dc(SSL_CTX *ctx);
void SSL_CTX_disable_sign_by_dc(SSL_CTX *ctx);
void SSL_enable_sign_by_dc(SSL *s);
void SSL_disable_sign_by_dc(SSL *s);
int SSL_get_delegated_credential_tag(SSL *s);
int SSL_verify_delegated_credential_signature(X509 *parent_cert,
                                              DELEGATED_CREDENTIAL *dc,
                                              int is_server);
int SSL_use_dc(SSL *ssl, DELEGATED_CREDENTIAL *dc);
int SSL_use_dc_file(SSL *ssl, const char *file, int type);
int SSL_use_dc_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int SSL_use_dc_PrivateKey_file(SSL *ssl, const char *file, int type);
int SSL_CTX_use_dc(SSL_CTX *ctx, DELEGATED_CREDENTIAL *dc);
int SSL_CTX_use_dc_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_dc_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_dc_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int DC_print(BIO *bp, DELEGATED_CREDENTIAL *dc);
int DC_sign(DELEGATED_CREDENTIAL *dc, EVP_PKEY *dc_pkey,
            unsigned int valid_time, int expect_verify_hash,
            X509 *ee_cert, EVP_PKEY *ee_pkey, const EVP_MD *md,
            int is_server);
# endif
```

## 描述

Delegated Credentials功能默认关闭，编译时需要增加编译选项enable-delegated-credential来开
启。以下简称为DC。

DC_new()创建一个新的DELEGATED_CREDENTIAL结构，返回DELEGATED_CREDENTIAL指针。
DC_new_ex()跟DC_new()类似，参数增加了**libctx**和**propq**，用于支持提供的provider。
DC_new_from_raw_byte()从**byte**中加载DELEGATED_CREDENTIAL，byte长度为len。
DC_new_from_raw_byte_ex()比DC_new_from_raw_byte()多了**libctx**和**propq**两个参数，
用于支持提供的provider。

DC_free()用于释放已经分配的**dc**结构。

DC_check_valid()检查**dc**是否合法，包括**dc**是否过期，**parent_cert**是否包含了特定的
满足签发dc要求的KeyUsage。

DC_check_time_valid()检查是否过期。
DC_check_parent_cert_valid()检查**parent_cert**是否可以签发dc。

DC_get_valid_time()用于获取**dc**的有效时间，单位为秒。
DC_get_expected_cert_verify_algorithm()获取期望使用的验签算法。

DC_get_dc_publickey_raw_len()获取已经编码的公钥长度，
DC_get0_dc_publickey_raw()获取已经编码的公钥，这里的公钥指SubjectPublicKeyInfo。

DC_get_signature_sign_algorithm()获取**dc**的签名所使用的签名算法。
DC_get_dc_signature_len()获取**dc**的签名长度。
DC_get0_dc_signature()获取**dc**的签名。

DC_get0_publickey(dc)获取dc的公钥，返回EVP_PKEY指针。
DC_get0_raw_byte()获取原始格式的dc。
DC_get_raw_byte_len()获取原始格式的dc的长度。

DC_set_valid_time()设置**dc**的有效时间为**valid_time**，单位为秒。
DC_set_expected_cert_verify_algorithm()设置期望的验签算法。
DC_set_dc_publickey_len()设置公钥长度。
DC_set0_dc_publickey()设置公钥，对应的是SubjectPublicKeyInfo的DER编码。
DC_set_signature_sign_algorithm()设置**dc**的签名算法为**alg**。
DC_set_dc_signature_len()设置**dc**的签名长度为**len**。
DC_set0_dc_signature()设置**dc**的签名为**sig**。
DC_set0_raw_byte()将裸格式的DC **byte**设置到**dc**上，byte长度为len，不拷贝byte。
DC_set1_raw_byte()将裸格式的DC **byte**设置到**dc**上，byte长度为len，同时拷贝byte。
DC_set0_publickey()将公钥**pkey**设置到**dc**上。

int DC_check_private_key(DELEGATED_CREDENTIAL *dc, EVP_PKEY *pkey);

DC_up_ref()将**dc**的引用计数加一。
DC_load_from_file()从文件**file**加载DC。
DC_load_from_file_ex()从文件**file**加载DC，并设置**libctx**和**propq**，支持使用提供的
provider。

SSL_CTX_enable_verify_peer_by_dc()，开启DC校验对端，作用于SSL_CTX。
SSL_CTX_disable_verify_peer_by_dc()，关闭DC校验对端，作用于SSL_CTX。
SSL_CTX_enable_sign_by_dc()，开启DC签名，作用于SSL_CTX。
SSL_CTX_disable_sign_by_dc()，关闭DC签名，作用于SSL_CTX。

SSL_enable_verify_peer_by_dc()，开启DC校验对端，作用于SSL。
SSL_disable_verify_peer_by_dc()，关闭DC校验对端，作用于SSL。
SSL_enable_sign_by_dc()，开启DC签名，作用于SSL。
SSL_disable_sign_by_dc()，关闭DC签名，作用于SSL。

SSL_get_delegated_credential_tag()用于从SSL获取DC状态标志位，返回值为以下几个数值按位或的
关系。
DC_REQ_HAS_BEEN_SEND_TO_PEER表示已经向对端发送DC request，这里的DC request指客户端发送
ClientHello消息中包含delegated_credential扩展，或者服务端发送CertificateRequest消息中包
含delegated_credential扩展。
DC_HAS_BEEN_USED_FOR_VERIFY_PEER表示已经使用DC校验对端身份；
DC_HAS_BEEN_USED_FOR_SIGN表示已经使用DC进行签名。

SSL_verify_delegated_credential_signature()使用证书parent_cert来校验dc中的签名，
is_server表示dc是否来自服务端，即客户端调用SSL_verify_delegated_credential_signature()
校验服务端dc时，is_server应为1。

SSL_CTX_use_dc()和SSL_use_dc()用于设置dc到SSL_CTX/SSL上。
SSL_CTX_use_dc_file()和SSL_use_dc_file()从文件中加载dc，type当前只支持
DC_FILETYPE_RAW。
注意：使用以上4个API设置dc的时候，需要先加载签发该dc的客户端或服务端证书，例如使用
SSL_CTX_use_certificate()， SSL_CTX_use_certificate_file()，
SSL_use_certificate(), SSL_use_certificate_file()等接口。

SSL_CTX_use_dc_PrivateKey()和SSL_use_dc_PrivateKey()设置dc的私钥，用法跟
SSL_CTX_use_PrivateKey/SSL_use_PrivateKey()相似。
SSL_CTX_use_dc_PrivateKey_file()和SSL_use_dc_PrivateKey_file()从文件中加载dc的私钥，
用法跟SSL_CTX_use_PrivateKey_file/SSL_use_PrivateKey_file()相似。

DC_print()将**dc**的各个字段输出到**bp**。
DC_sign()使用客户端或服务端证书来给**dc**签名，**ee_cert**为端证书，**ee_pkey**为与之对应的
密钥，**dc_pkey**为dc的公钥，**valid_time**为有效时间（单位为秒），
**expect_verify_hash**为对应CertificateVerify中的签名算法对应的hash算法。**md**为签名时
使用的摘要算法。

## 返回值

返回值为int型所有函数，返回1表示成功，返回0表示失败。

## 示例

服务端集成DC功能：

```c

#include <openssl/ssl.h>
#include <openssl/x509.h>

SSL *s;
SSL_CTX *ctx;
const char *cert_file = "/path/to/cert";
const char *key_file = "/path/to/key";
const char *dc_file = "/path/to/dc";
const char *dc_key_file = "/path/to/dc_key";

if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL)
    /* Error */

/* 加载服务端证书 */
if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM))
    /* Error */

/* 加载服务端证书的私钥 */
if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM))
    /* Error */

/* 加载dc */
if (!SSL_CTX_use_dc_file(ctx, dc_file, DC_FILETYPE_RAW))
    /* Error */

/* 加载dc的私钥 */
if (!SSL_CTX_use_dc_PrivateKey_file(ctx, dc_key_file, SSL_FILETYPE_PEM))
    /* Error */

/* 开启dc签名功能，服务端使用dc代替服务端证书进行签名 */
SSL_CTX_enable_sign_by_dc(ctx);

if ((s = SSL_new(ctx)) == NULL)
    /* Error */
```

客户端集成DC功能：

```c

#include <openssl/ssl.h>

SSL *s;
SSL_CTX *ctx;
const char *cert_file = "/path/to/cert";
const char *key_file = "/path/to/key";

if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
    /* Error */

/* 加载客户端证书 */
if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM))
    /* Error */

/* 加载客户端证书的私钥 */
if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM))
    /* Error */

/* 开启dc验签，客户端使用服务端的dc来验证签名 */
SSL_CTX_enable_verify_peer_by_dc(ctx);

if ((s = SSL_new(ctx)) == NULL)
    /* Error */
```

## 历史

BabaSSL 8.2.0中增加以上接口。

## 版权

版权归Tongsuo项目作者所有。

该文件使用Apache 2.0许可证，请在遵守许可证的前提下使用该文件，可通过以下链接获取
[许可证副本](https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt)。
