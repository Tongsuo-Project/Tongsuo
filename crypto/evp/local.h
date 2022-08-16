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

int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

void bsaes_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char ivec[16], int enc);
void bsaes_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const AES_KEY *key,
                                const unsigned char ivec[16]);
void bsaes_xts_encrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
void bsaes_xts_decrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);

void AES_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const AES_KEY *key,
                       const unsigned char ivec[AES_BLOCK_SIZE]);

void AES_xts_encrypt(const unsigned char *inp, unsigned char *out, size_t len,
                     const AES_KEY *key1, const AES_KEY *key2,
                     const unsigned char iv[16]);
void AES_xts_decrypt(const unsigned char *inp, unsigned char *out, size_t len,
                     const AES_KEY *key1, const AES_KEY *key2,
                     const unsigned char iv[16]);

int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length, const AES_KEY *key, int enc);
void aesni_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

void aesni_ocb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);
void aesni_ocb_decrypt(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       size_t start_block_num,
                       unsigned char offset_i[16],
                       const unsigned char L_[][16],
                       unsigned char checksum[16]);

void aesni_ctr32_encrypt_blocks(const unsigned char *in,
                                unsigned char *out,
                                size_t blocks,
                                const void *key, const unsigned char *ivec);

void aesni_xts_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16]);

void aesni_xts_decrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16]);

void aesni_ccm64_encrypt_blocks(const unsigned char *in,
                                unsigned char *out,
                                size_t blocks,
                                const void *key,
                                const unsigned char ivec[16],
                                unsigned char cmac[16]);

void aesni_ccm64_decrypt_blocks(const unsigned char *in,
                                unsigned char *out,
                                size_t blocks,
                                const void *key,
                                const unsigned char ivec[16],
                                unsigned char cmac[16]);

size_t aesni_gcm_encrypt(const unsigned char *in,
                         unsigned char *out,
                         size_t len,
                         const void *key, unsigned char ivec[16], u64 *Xi);
size_t aesni_gcm_decrypt(const unsigned char *in,
                         unsigned char *out,
                         size_t len,
                         const void *key, unsigned char ivec[16], u64 *Xi);
void gcm_ghash_avx(u64 Xi[2], const u128 Htable[16], const u8 *in,
                   size_t len);

size_t aes_gcm_enc_128_kernel(const uint8_t * plaintext, uint64_t plaintext_length, uint8_t * ciphertext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
size_t aes_gcm_enc_192_kernel(const uint8_t * plaintext, uint64_t plaintext_length, uint8_t * ciphertext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
size_t aes_gcm_enc_256_kernel(const uint8_t * plaintext, uint64_t plaintext_length, uint8_t * ciphertext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
size_t aes_gcm_dec_128_kernel(const uint8_t * ciphertext, uint64_t plaintext_length, uint8_t * plaintext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
size_t aes_gcm_dec_192_kernel(const uint8_t * ciphertext, uint64_t plaintext_length, uint8_t * plaintext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
size_t aes_gcm_dec_256_kernel(const uint8_t * ciphertext, uint64_t plaintext_length, uint8_t * plaintext,
                              uint64_t *Xi, unsigned char ivec[16], const void *key);
void gcm_ghash_v8(u64 Xi[2],const u128 Htable[16],const u8 *inp, size_t len);

int aes_v8_set_encrypt_key(const unsigned char *userKey, const int bits,
                          AES_KEY *key);
int aes_v8_set_decrypt_key(const unsigned char *userKey, const int bits,
                          AES_KEY *key);
void aes_v8_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void aes_v8_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void aes_v8_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       unsigned char *ivec, const int enc);
void aes_v8_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const AES_KEY *key,
                       const int enc);
void aes_v8_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
void aes_v8_xts_encrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);
void aes_v8_xts_decrypt(const unsigned char *inp, unsigned char *out,
                       size_t len, const AES_KEY *key1,
                       const AES_KEY *key2, const unsigned char iv[16]);

void sha1_multi_block(SHA1_MB_CTX *, const HASH_DESC *, int);
void aesni_multi_cbc_encrypt(CIPH_DESC *, void *, int);

void sha256_multi_block(SHA256_MB_CTX *, const HASH_DESC *, int);
void aesni_multi_cbc_encrypt(CIPH_DESC *, void *, int);

void *xor128_encrypt_n_pad(void *out, const void *inp, void *otp, size_t len);
void *xor128_decrypt_n_pad(void *out, const void *inp, void *otp, size_t len);

void aesni_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

int aesni_cbc_sha256_enc(const void *inp, void *out, size_t blocks,
                         const AES_KEY *key, unsigned char iv[16],
                         SHA256_CTX *ctx, const void *in0);

void aesni_cbc_sha1_enc(const void *inp, void *out, size_t blocks,
                        const AES_KEY *key, unsigned char iv[16],
                        SHA_CTX *ctx, const void *in0);

void aesni256_cbc_sha1_dec(const void *inp, void *out, size_t blocks,
                           const AES_KEY *key, unsigned char iv[16],
                           SHA_CTX *ctx, const void *in0);

void rc4_md5_enc(RC4_KEY *key, const void *in0, void *out,
                 MD5_CTX *ctx, const void *inp, size_t blocks);

int sm4_v8_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int sm4_v8_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void sm4_v8_encrypt(const unsigned char *in, unsigned char *out,
                    const SM4_KEY *key);
void sm4_v8_decrypt(const unsigned char *in, unsigned char *out,
                    const SM4_KEY *key);
void sm4_v8_cbc_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const SM4_KEY *key,
                        unsigned char *ivec, const int enc);
void sm4_v8_ecb_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const SM4_KEY *key,
                        const int enc);
void sm4_v8_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key,
                                 const unsigned char ivec[16]);

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                   size_t r);
void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);

