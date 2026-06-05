#ifndef API_H
#define API_H

#include <stdint.h>

#define ossl_ml_kem_512_avx2_SECRETKEYBYTES 1632
#define ossl_ml_kem_512_avx2_PUBLICKEYBYTES 800
#define ossl_ml_kem_512_avx2_CIPHERTEXTBYTES 768
#define ossl_ml_kem_512_avx2_KEYPAIRCOINBYTES 64
#define ossl_ml_kem_512_avx2_ENCCOINBYTES 32
#define ossl_ml_kem_512_avx2_BYTES 32

int ossl_ml_kem_512_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
int ossl_ml_kem_512_avx2_keypair(uint8_t *pk, uint8_t *sk);
int ossl_ml_kem_512_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_512_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ossl_ml_kem_512_avx2_dec(uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk);

#define ossl_ml_kem_768_avx2_SECRETKEYBYTES 2400
#define ossl_ml_kem_768_avx2_PUBLICKEYBYTES 1184
#define ossl_ml_kem_768_avx2_CIPHERTEXTBYTES 1088
#define ossl_ml_kem_768_avx2_KEYPAIRCOINBYTES 64
#define ossl_ml_kem_768_avx2_ENCCOINBYTES 32
#define ossl_ml_kem_768_avx2_BYTES 32

int ossl_ml_kem_768_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
int ossl_ml_kem_768_avx2_keypair(uint8_t *pk, uint8_t *sk);
int ossl_ml_kem_768_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_768_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ossl_ml_kem_768_avx2_dec(uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk);

#define ossl_ml_kem_1024_avx2_SECRETKEYBYTES 3168
#define ossl_ml_kem_1024_avx2_PUBLICKEYBYTES 1568
#define ossl_ml_kem_1024_avx2_CIPHERTEXTBYTES 1568
#define ossl_ml_kem_1024_avx2_KEYPAIRCOINBYTES 64
#define ossl_ml_kem_1024_avx2_ENCCOINBYTES 32
#define ossl_ml_kem_1024_avx2_BYTES 32

int ossl_ml_kem_1024_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                         const uint8_t *coins);
int ossl_ml_kem_1024_avx2_keypair(uint8_t *pk, uint8_t *sk);
int ossl_ml_kem_1024_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_1024_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ossl_ml_kem_1024_avx2_dec(uint8_t *ss, const uint8_t *ct,
                              const uint8_t *sk);

#endif
