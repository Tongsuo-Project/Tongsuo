/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_ML_DSA_LOCAL_H
#define OSSL_CRYPTO_ML_DSA_LOCAL_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>

#include "crypto/ml_dsa.h"

/*
 parameters for ML-DSA-44、65、87 respectively
 */
#if ML_DSA_MODE == 44
#define ML_DSA_K 4
#define ML_DSA_L 4
#define ML_DSA_ETA 2
#define ML_DSA_TAU 39
#define ML_DSA_BETA 78
#define ML_DSA_GAMMA1 (1 << 17)
#define ML_DSA_GAMMA2 ((ML_DSA_Q-1)/88)
#define ML_DSA_OMEGA 80
#define ML_DSA_CTILDEBYTES 32

#elif ML_DSA_MODE == 65
#define ML_DSA_K 6
#define ML_DSA_L 5
#define ML_DSA_ETA 4
#define ML_DSA_TAU 49
#define ML_DSA_BETA 196
#define ML_DSA_GAMMA1 (1 << 19)
#define ML_DSA_GAMMA2 ((ML_DSA_Q-1)/32)
#define ML_DSA_OMEGA 55
#define ML_DSA_CTILDEBYTES 48


#elif ML_DSA_MODE == 87
#define ML_DSA_K 8
#define ML_DSA_L 7
#define ML_DSA_ETA 2
#define ML_DSA_TAU 60
#define ML_DSA_BETA 120
#define ML_DSA_GAMMA1 (1 << 19)
#define ML_DSA_GAMMA2 ((ML_DSA_Q-1)/32)
#define ML_DSA_OMEGA 75
#define ML_DSA_CTILDEBYTES 64

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (ML_DSA_OMEGA + ML_DSA_K)

#if ML_DSA_GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif ML_DSA_GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if ML_DSA_GAMMA2 == (ML_DSA_Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif ML_DSA_GAMMA2 == (ML_DSA_Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ML_DSA_ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ML_DSA_ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#endif
