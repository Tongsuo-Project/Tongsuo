/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2024 Nexus-TYF. All Rights Reserved.
 * Ported from Nexus-TYF.
 * 
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef _WBSM4_H_
#define _WBSM4_H_

#include <openssl/core.h>

# if defined(OPENSSL_NO_WBSM4_XIAOLAI) && defined(OPENSSL_NO_WBSM4_BAIWU) && \
     defined(OPENSSL_NO_WBSM4_WSISE)
#  error WBSM4 is disabled.
# endif

#include "wbstructure.h"

void wbsm4_sm4_setkey(uint32_t SK[32], const uint8_t key[16]);

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
#pragma pack(push, 1)
typedef struct {
    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    Aff32 SE[4];
    Aff32 FE[4];
    uint32_t Table[32][4][256];
} wbsm4_xiaolai_key;
#pragma pack(pop)

void wbsm4_xiaolai_gen(const uint8_t *sm4_key, wbsm4_xiaolai_key *wbsm4_key);
void wbsm4_xiaolai_encrypt(const unsigned char IN[], unsigned char OUT[],
                           const wbsm4_xiaolai_key *wbsm4_key);
void wbsm4_xiaolai_set_key(const uint8_t *key, wbsm4_xiaolai_key *wbsm4_key);
void wbsm4_xiaolai_export_key(const wbsm4_xiaolai_key *wbsm4_key,
                              uint8_t *key);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
#pragma pack(push, 1)
typedef struct {
    Aff32 SE[4];
    Aff32 FE[4];
    uint32_t TD[32][4][4][256];
    uint32_t TR[32][4][256][256];
} wbsm4_baiwu_key;
#pragma pack(pop)

void wbsm4_baiwu_gen(const uint8_t *sm4_key, wbsm4_baiwu_key *wbsm4_key);
void wbsm4_baiwu_encrypt(const unsigned char IN[], unsigned char OUT[],
                         const wbsm4_baiwu_key *wbsm4_key);
void wbsm4_baiwu_set_key(const uint8_t *key, wbsm4_baiwu_key *wbsm4_key);
void wbsm4_baiwu_export_key(const wbsm4_baiwu_key *wbsm4_key, uint8_t *key);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
#pragma pack(push, 1)
typedef struct {
    Aff32 M[32][3];
    Aff32 C[32];
    Aff32 D[32];
    Aff32 SE[4];
    Aff32 FE[4];
    uint64_t Table[32][4][256];
} wbsm4_wsise_key;
#pragma pack(pop)

void wbsm4_wsise_gen(const uint8_t *sm4_key, wbsm4_wsise_key *wbsm4_key);
void wbsm4_wsise_encrypt(const unsigned char IN[], unsigned char OUT[],
                         const wbsm4_wsise_key *wbsm4_key);
void wbsm4_wsise_set_key(const uint8_t *key, wbsm4_wsise_key *wbsm4_key);
void wbsm4_wsise_export_key(const wbsm4_wsise_key *wbsm4_key, uint8_t *key);
#endif /* OPENSSL_NO_WBSM4_WSISE */

#endif /* _WBSM4_H_ */
