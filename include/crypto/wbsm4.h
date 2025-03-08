#ifndef WBCRYPTO_WBSM4_H
#define WBCRYPTO_WBSM4_H

#include "WBMatrix/WBMatrix.h"
#include "sm4.h"
#include "stdint.h"

#define WBSM4_ENCRYPT_MODE 1
#define WBSM4_DECRYPT_MODE 0

extern const uint8_t SM4_SBOX[256];
extern const M32 SM4_L_matrix;

#define GET32(pc)  (\
((uint32_t)(pc)[0] << 24) ^\
((uint32_t)(pc)[1] << 16) ^\
((uint32_t)(pc)[2] <<  8) ^\
((uint32_t)(pc)[3]))

#define PUT32(st, ct)\
(ct)[0] = (uint8_t)((st) >> 24);\
(ct)[1] = (uint8_t)((st) >> 16);\
(ct)[2] = (uint8_t)((st) >>  8);\
(ct)[3] = (uint8_t)(st)

typedef struct {
    uint8_t lut[8][16];      // 8 个 16 维的 4-bit 双射表
} Biject32;

typedef struct {
    int mode;
    uint8_t ***P1;      // P1[32][8][256];
    uint8_t ***P2;      // P2[32][8][256];
    uint8_t ***Q1;      // Q1[32][8][256];
    uint8_t ***Q2;      // Q2[32][8][256];
    uint8_t ***Q3;      // Q3[32][8][256];
    uint8_t ***Q4;      // Q4[32][8][256];

    Biject32 SE[4];
    Biject32 FE[4];

    uint32_t T[32][4][256];

} wbsm4_jin_stkey_context;

typedef struct {
    int mode;
    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    Aff32 SE[4];
    Aff32 FE[4];
    uint32_t Table[32][4][256];
} wbsm4_xiao_stkey_context;

typedef struct {
    int mode;

    uint32_t wbrk[32];
    uint8_t Xor32Table[32][4][256][256];
    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    Aff32 SE[4];
    Aff32 FE[4];
    uint32_t Table[32][4][256];
} wbsm4_xiao_dykey_context;

typedef struct {
    int mode;
    Aff32 Ek[32];
    Biject32 R[32];
} wbsm4_xiao_dykey_ctxrk;

void wbsm4_setkey_enc(uint32_t rk[32], const unsigned char key[16]);
void wbsm4_setkey_dec(uint32_t rk[32], const unsigned char key[16]);

void gen_Bijection4pair(uint8_t *table, uint8_t *inverse_table);
void gen_Bijection32pair(Biject32 *bij, Biject32 *bij_inv);
uint32_t BijectionU32(const Biject32* bij, uint32_t x);
void gen_BijectXor32_table(Biject32 *in1, Biject32 *in2, Biject32* out, uint8_t lut[8][256]);
uint32_t BijectXor32(uint8_t lut[8][256], uint32_t x, uint32_t y);

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
// execute on trusted environment only
void wbsm4_xiao_stkey_gen(const uint8_t *key, wbsm4_xiao_stkey_context *ctx);
// execute on whitebox environment
void wbsm4_xiao_stkey_set_key(const uint8_t *key, wbsm4_xiao_stkey_context *ctx);
void wbsm4_xiao_stkey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_stkey_context *ctx);
void wbsm4_xiao_stkey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_stkey_context *ctx);
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
// execute on trusted environment only
void wbsm4_xiao_dykey_gen(const uint8_t *key, wbsm4_xiao_dykey_context *ctx, wbsm4_xiao_dykey_ctxrk *ctxrk);
void wbsm4_xiao_dykey_key2wbrk(uint8_t *key, wbsm4_xiao_dykey_ctxrk *ctxrk, uint32_t wbrk[32]);
// execute on whitebox environment
void wbsm4_xiao_dykey_update_wbrk(wbsm4_xiao_dykey_context *ctx, uint32_t wbrk[32]);
void wbsm4_xiao_dykey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx);
void wbsm4_xiao_dykey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx);
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
// execute on trusted environment only
void wbsm4_jin_stkey_gen(const uint8_t *key, wbsm4_jin_stkey_context *ctx);
// execute on whitebox environment
void wbsm4_jin_stkey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx);
void wbsm4_jin_stkey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx);
#endif

#endif //WBCRYPTO_WBSM4_H