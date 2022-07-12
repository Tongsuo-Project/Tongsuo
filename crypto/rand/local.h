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

size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(unsigned char *buf, size_t len);

extern unsigned int OPENSSL_ia32cap_P[];
