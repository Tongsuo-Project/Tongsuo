/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * This header file is only used for the --symbol-prefix search export symbol.
 */

/* Interface to assembler module */
unsigned int padlock_capability(void);
void padlock_key_bswap(AES_KEY *key);
void padlock_verify_context(struct padlock_cipher_data *ctx);
void padlock_reload_key(void);
void padlock_aes_block(void *out, const void *inp,
                       struct padlock_cipher_data *ctx);
int padlock_ecb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_cbc_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_cfb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_ofb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_ctr32_encrypt(void *out, const void *inp,
                          struct padlock_cipher_data *ctx, size_t len);
int padlock_xstore(void *out, int edx);
void padlock_sha1_oneshot(void *ctx, const void *inp, size_t len);
void padlock_sha1(void *ctx, const void *inp, size_t len);
void padlock_sha256_oneshot(void *ctx, const void *inp, size_t len);
void padlock_sha256(void *ctx, const void *inp, size_t len);
