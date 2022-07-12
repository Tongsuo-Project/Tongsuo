/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

/*
 * This header file is only used for the --symbol-prefix search export symbol.
 */

int x25519_fe64_eligible(void);
void x25519_fe64_mul(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_sqr(fe64 h, const fe64 f);
void x25519_fe64_mul121666(fe64 h, fe64 f);
void x25519_fe64_add(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_sub(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_tobytes(uint8_t *s, const fe64 f);
void x25519_fe51_mul(fe51 h, const fe51 f, const fe51 g);
void x25519_fe51_sqr(fe51 h, const fe51 f);
void x25519_fe51_mul121666(fe51 h, fe51 f);
