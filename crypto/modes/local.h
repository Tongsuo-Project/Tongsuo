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

void gcm_init_clmul(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_clmul(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_clmul(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                     size_t len);
void gcm_init_avx(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_avx(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_avx(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
void gcm_gmult_4bit_mmx(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit_mmx(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                        size_t len);

void gcm_gmult_4bit_x86(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit_x86(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                        size_t len);
void gcm_init_neon(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_neon(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_neon(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);
void gcm_init_v8(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_v8(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_v8(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                  size_t len);
void gcm_init_p8(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_p8(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_p8(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                  size_t len);

void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);
