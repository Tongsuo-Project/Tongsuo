#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "ml_dsa_local.h"

#define power2round ML_DSA_NAMESPACE(power2round)
int32_t power2round(int32_t *a0, int32_t a);

#define decompose ML_DSA_NAMESPACE(decompose)
int32_t decompose(int32_t *a0, int32_t a);

#define make_hint ML_DSA_NAMESPACE(make_hint)
unsigned int make_hint(int32_t a0, int32_t a1);

#define use_hint ML_DSA_NAMESPACE(use_hint)
int32_t use_hint(int32_t a, unsigned int hint);

#endif
