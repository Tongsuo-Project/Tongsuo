#ifndef ML_DSA_AVX2_TARGET_H
#define ML_DSA_AVX2_TARGET_H

#if defined(__clang__)

# define ML_DSA_AVX2_TARGET_BEGIN \
    _Pragma("clang attribute push (__attribute__((target(\"avx2,bmi2,popcnt\"))), apply_to=function)")
# define ML_DSA_AVX2_TARGET_END \
    _Pragma("clang attribute pop")

#elif defined(__GNUC__)

# define ML_DSA_AVX2_TARGET_BEGIN \
    _Pragma("GCC push_options")   \
    _Pragma("GCC target(\"avx2,bmi2,popcnt\")")
# define ML_DSA_AVX2_TARGET_END \
    _Pragma("GCC pop_options")

#else

# define ML_DSA_AVX2_TARGET_BEGIN
# define ML_DSA_AVX2_TARGET_END

#endif

#endif
