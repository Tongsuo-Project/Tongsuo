/*
 * ML-KEM AVX2 C sources use AVX2/BMI2/POPCNT intrinsics even when the
 * surrounding build does not pass per-file target flags.
 *
 * Every translation unit that includes this header must also include
 * ml_kem_avx2_target_end.h at the very end of the file.
 */
#ifndef ML_KEM_AVX2_TARGET_H
# define ML_KEM_AVX2_TARGET_H

# if defined(__clang__) && !defined(__ASSEMBLER__)
   /*
    * Clang does not support '#pragma GCC target' and warns about it with
    * -Wunknown-pragmas, which becomes an error under --strict-warnings.
    * Use Clang's own attribute pragma instead; the push must be balanced
    * by a pop before the end of the translation unit.
    */
#  pragma clang attribute push (__attribute__((target("avx2,bmi2,popcnt"))), apply_to=function)
# elif defined(__GNUC__) && !defined(__ASSEMBLER__)
#  pragma GCC target("avx2,bmi2,popcnt")
# endif

#endif
