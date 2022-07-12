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

void _armv7_neon_probe(void);
void _armv8_aes_probe(void);
void _armv8_sha1_probe(void);
void _armv8_sha256_probe(void);
void _armv8_pmull_probe(void);
# ifdef __aarch64__
void _armv8_sm3_probe(void);
void _armv8_sm4_probe(void);
void _armv8_sha512_probe(void);
# endif
uint32_t _armv7_tick(void);

uint32_t OPENSSL_rdtsc(void);

IA32CAP OPENSSL_ia32_cpuid(unsigned int *);
