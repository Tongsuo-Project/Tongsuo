#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"
#include <openssl/crypto.h>

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif
//这个版本允许用户提供额外的随机熵来源（coins）
#define crypto_kem_keypair_derand KYBER_NAMESPACE(keypair_derand)
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
//这个版本的加密函数允许用户传入固定的随机熵（coins），以控制加密过程中使用的随机性。
#define crypto_kem_enc_derand KYBER_NAMESPACE(enc_derand)
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// 导出函数声明
OPENSSL_EXPORT int pqcrystals_kyber768_ref_keypair(unsigned char *pk, unsigned char *sk);
OPENSSL_EXPORT int pqcrystals_kyber768_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
OPENSSL_EXPORT int pqcrystals_kyber768_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);



#endif
