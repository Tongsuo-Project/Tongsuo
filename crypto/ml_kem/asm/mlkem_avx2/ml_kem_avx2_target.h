/*
 * ML-KEM AVX2 C sources use AVX2/BMI2/POPCNT intrinsics even when the
 * surrounding build does not pass per-file target flags.
 */
#ifndef ML_KEM_AVX2_TARGET_H
# define ML_KEM_AVX2_TARGET_H

# if (defined(__GNUC__) || defined(__clang__)) && !defined(__ASSEMBLER__)
#  pragma GCC target("avx2,bmi2,popcnt")
# endif

#endif
