/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/async.h>

/*
 * If we haven't managed to detect any other async architecture then we default
 * to NULL.
 */
#ifndef ASYNC_ARCH
# define ASYNC_NULL
# define ASYNC_ARCH

typedef struct async_fibre_st {
    int dummy;
} async_fibre;

# ifdef async_fibre_swapcontext
#  undef async_fibre_swapcontext
# endif
# define async_fibre_swapcontext(o,n,r)         0
# ifdef async_fibre_makecontext
#  undef async_fibre_makecontext
# endif
# define async_fibre_makecontext(c)             0
# ifdef async_fibre_free
#  undef async_fibre_free
# endif
# define async_fibre_free(f)
# ifdef async_fibre_init_dispatcher
#  undef async_fibre_init_dispatcher
# endif
# define async_fibre_init_dispatcher(f)

#endif
