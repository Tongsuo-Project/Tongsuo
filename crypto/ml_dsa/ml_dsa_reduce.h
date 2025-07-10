#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "ml_dsa_local.h"

#define MONT -4186625 // 2^32 % ML_DSA_Q
#define QINV 58728449 // q^(-1) mod 2^32

#define montgomery_reduce ML_DSA_NAMESPACE(montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

#define reduce32 ML_DSA_NAMESPACE(reduce32)
int32_t reduce32(int32_t a);

#define caddq ML_DSA_NAMESPACE(caddq)
int32_t caddq(int32_t a);

#define freeze ML_DSA_NAMESPACE(freeze)
int32_t freeze(int32_t a);

#endif
