/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EBCDIC_H
# define OPENSSL_EBCDIC_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_EBCDIC_H
# endif

# include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Avoid name clashes with other applications */
# ifdef os_toascii
#  undef os_toascii
# endif
# define os_toascii   _openssl_os_toascii
# ifdef os_toebcdic
#  undef os_toebcdic
# endif
# define os_toebcdic  _openssl_os_toebcdic
# ifdef ebcdic2ascii
#  undef ebcdic2ascii
# endif
# define ebcdic2ascii _openssl_ebcdic2ascii
# ifdef ascii2ebcdic
#  undef ascii2ebcdic
# endif
# define ascii2ebcdic _openssl_ascii2ebcdic

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);

#ifdef  __cplusplus
}
#endif
#endif
