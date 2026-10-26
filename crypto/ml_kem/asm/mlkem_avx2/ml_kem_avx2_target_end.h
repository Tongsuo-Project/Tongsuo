/*
 * Ends the '#pragma clang attribute push' started by
 * ml_kem_avx2_target.h.  Include this header at the very end of every
 * translation unit that includes ml_kem_avx2_target.h; Clang warns
 * about unbalanced pushes and Tongsuo builds with -Werror.
 */
#ifndef ML_KEM_AVX2_TARGET_END_H
# define ML_KEM_AVX2_TARGET_END_H

# if defined(__clang__) && !defined(__ASSEMBLER__)
#  pragma clang attribute pop
# endif

#endif
