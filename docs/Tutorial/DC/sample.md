# 应用程序使用Delegated Credentials的例子

服务器端代码示例：

~~~
#include <openssl/x509.h>

const char *cert_file;
const char *key_file;
const char *dc_file;
const char *dc_key_file;

int main()
{
    SSL *s;
    SSL_CTX *ctx;
	DELEGATED_CREDENTIAL *dc = NULL;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
    	// error
    }

    // 设置证书
    if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
    	// error
    }
    // 设置证书的密钥
    if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
    	// error
    }

    // 加载DC文件，注意：必须先加载服务端（或客户端）证书，再加载DC
    if (!SSL_CTX_use_dc_file(ctx, cert_file, 0)) {
    	// error
    }

    // 加载DC的密钥
    if (!SSL_CTX_use_dc_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
    	// error
    }

    //功能：开启dc签名功能，server在开启该功能并收到dc请求时才会选择使用dc进行签名
    SSL_CTX_enable_sign_by_dc(ctx);

    ...

    s = SSL_new(ctx);

    ...

    return 0;
}
~~~

客户端代码示例

~~~
#include <openssl/x509.h>

const char *cert_file;
const char *key_file;

int main()
{
    SSL *s;
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
    	// error
    }

    // 设置证书
    if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
    	// error
    }
    // 设置证书的密钥
    if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
    	// error
    }

    /* 功能：开启dc校验，client在tls握手中会发送dc-request表明自己支持使用dc；
     * 如果服务端支持DC，会在服务器证书扩展中携带DC，使用DC进行后续的身份认证
     */
    SSL_CTX_enable_verify_peer_by_dc(ctx);

    ...

    s = SSL_new(ctx);

    ...

    return 0;
}
~~~
