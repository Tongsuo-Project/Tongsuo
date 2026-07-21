#include "ml_dsa_local.h"


// #if defined(ML_DSA_AVX2_ASM) && defined(OPENSSL_CPUID_OBJ) \
//     && (defined(__x86_64) || defined(__x86_64__) \
//         || defined(_M_AMD64) || defined(_M_X64))
# include "internal/cryptlib.h"
# include <openssl/evp.h>

# define ML_DSA_AVX2_CAPABLE (OPENSSL_ia32cap_P[2] & (1 << 5))
# define ML_DSA_BMI2_CAPABLE (OPENSSL_ia32cap_P[2] & (1 << 8))
# define ML_DSA_POPCNT_CAPABLE (OPENSSL_ia32cap_P[1] & (1 << 23))



int ossl_ml_dsa_avx2_capable(void)
{
    return ML_DSA_AVX2_CAPABLE != 0
        && ML_DSA_BMI2_CAPABLE != 0
        && ML_DSA_POPCNT_CAPABLE != 0;
}

// #endif