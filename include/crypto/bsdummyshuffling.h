/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <stdint.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
 
typedef unsigned long long W;
typedef unsigned short A;
typedef unsigned char B;

enum OP {XOR, AND, OR, NOT};

void WBSM4_bsdummyshuffling_enc(B *in, B *out);
void WBSM4_bsdummyshuffling_dec(B *in, B *out);

