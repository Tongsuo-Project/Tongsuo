#ifndef ML_DSA_AVX2_TARGET_H
#define ML_DSA_AVX2_TARGET_H

#if defined(__GNUC__) || defined(__clang__)
# pragma GCC target("avx2,bmi2,popcnt")
#endif

#endif
