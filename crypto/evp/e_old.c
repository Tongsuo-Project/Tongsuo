/*
 * Copyright 2004-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <openssl/evp.h>

/*
 * Define some deprecated functions, so older programs don't crash and burn
 * too quickly.  On Windows, these will never be used, since
 * functions and variables in shared libraries are selected by entry point
 * location, not by name.
 */

#ifndef OPENSSL_NO_DES
# undef EVP_des_cfb
const EVP_CIPHER *EVP_des_cfb(void);
const EVP_CIPHER *EVP_des_cfb(void)
{
    return EVP_des_cfb64();
}

# undef EVP_des_ede3_cfb
const EVP_CIPHER *EVP_des_ede3_cfb(void);
const EVP_CIPHER *EVP_des_ede3_cfb(void)
{
    return EVP_des_ede3_cfb64();
}

# undef EVP_des_ede_cfb
const EVP_CIPHER *EVP_des_ede_cfb(void);
const EVP_CIPHER *EVP_des_ede_cfb(void)
{
    return EVP_des_ede_cfb64();
}
#endif

#ifndef OPENSSL_NO_RC5
# undef EVP_rc5_32_12_16_cfb
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void)
{
    return EVP_rc5_32_12_16_cfb64();
}
#endif

#undef EVP_aes_128_cfb
const EVP_CIPHER *EVP_aes_128_cfb(void);
const EVP_CIPHER *EVP_aes_128_cfb(void)
{
    return EVP_aes_128_cfb128();
}

#undef EVP_aes_192_cfb
const EVP_CIPHER *EVP_aes_192_cfb(void);
const EVP_CIPHER *EVP_aes_192_cfb(void)
{
    return EVP_aes_192_cfb128();
}

#undef EVP_aes_256_cfb
const EVP_CIPHER *EVP_aes_256_cfb(void);
const EVP_CIPHER *EVP_aes_256_cfb(void)
{
    return EVP_aes_256_cfb128();
}
