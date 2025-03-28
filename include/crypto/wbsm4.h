/*
* Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
* Copyright 2024 Nexus-TYF. All Rights Reserved.
* Ported from Nexus-TYF/Xiao-Lai-White-box-SM4.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
*/
#ifndef WBCRYPTO_WBSM4_H
#define WBCRYPTO_WBSM4_H

#include "WBMatrix.h"
#include <stdint.h>
#include <string.h>

#define WBSM4_ENCRYPT_MODE 1
#define WBSM4_DECRYPT_MODE 0

extern const uint8_t SM4_SBOX[256];
extern const M32 SM4_L_matrix;

#define GET32(pc)  \
(((uint32_t)(pc)[0] << 24) ^\
((uint32_t)(pc)[1] << 16) ^\
((uint32_t)(pc)[2] <<  8) ^\
((uint32_t)(pc)[3]))

#define PUT32(st, ct)\
(ct)[0] = (uint8_t)((st) >> 24);\
(ct)[1] = (uint8_t)((st) >> 16);\
(ct)[2] = (uint8_t)((st) >>  8);\
(ct)[3] = (uint8_t)(st)

typedef struct {
    uint8_t lut[8][16];      /*  8 个 16 维的 4-bit 双射表 */
} Biject32;

void wbsm4_export_key(const void *ctx, uint8_t *key, size_t len_ctx);
void wbsm4_set_key(const uint8_t *key, void *ctx, size_t len_ctx);

void gen_Bijection32pair(Biject32 *bij, Biject32 *bij_inv);
uint32_t BijectionU32(const Biject32* bij, uint32_t x);

typedef struct {
    int mode;

    uint32_t wbrk[32];
    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    Aff32 SE[4];
    Aff32 FE[4];
    uint32_t Table[32][4][256];
    uint8_t Xor32Table[32][4][256][256];
} wbsm4_xiao_dykey_context;

typedef struct {
    int mode;
    Aff32 Ek[32];
    Biject32 R[32];
} wbsm4_xiao_dykey_ctxrk;

/*  execute on trusted environment only */
void wbsm4_xiao_dykey_gen(const uint8_t *key, wbsm4_xiao_dykey_context *ctx, wbsm4_xiao_dykey_ctxrk *ctxrk);
void wbsm4_xiao_dykey_key2wbrk(uint8_t *key, wbsm4_xiao_dykey_ctxrk *ctxrk, uint32_t wbrk[32]);
/*  execute on whitebox environment */
void wbsm4_xiao_dykey_update_wbrk(wbsm4_xiao_dykey_context *ctx, uint32_t wbrk[32]);
void wbsm4_xiao_dykey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx);
void wbsm4_xiao_dykey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx);

#endif /* WBCRYPTO_WBSM4_H */
