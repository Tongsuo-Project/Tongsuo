/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _align_h_
#define _align_h_

#include "immintrin.h"

#define ALIGNED_UINT8(N)                                                       \
union {                                                                      \
uint8_t coeffs[N];                                                         \
__m256i vec[((N) + 31) / 32];                                              \
}

#define ALIGNED_INT32(N)                                                       \
union {                                                                      \
int32_t coeffs[N];                                                         \
__m256i vec[((N) + 7) / 8];                                                \
}


/* on Mac OS-X and possibly others, ALIGN(x) is defined in param.h, and -Werror chokes on the redef. */
#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN(x) __attribute__ ((aligned(x)))
#elif defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#elif defined(__ARMCC_VERSION)
#define ALIGN(x) __align(x)
#else
#define ALIGN(x)
#endif

#endif
