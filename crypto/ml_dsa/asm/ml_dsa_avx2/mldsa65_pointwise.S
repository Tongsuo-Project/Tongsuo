#define DILITHIUM_MODE 3
#define ML_DSA_AVX2_PREFIX ossl_ml_dsa_65_avx2_
#define ML_DSA_AVX2_ASM_SYM(s) ossl_ml_dsa_65_avx2_ ## s
#include "ntt/pointwise.S"
