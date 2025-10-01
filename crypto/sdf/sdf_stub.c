/*
 * SDF stub for builds with sdf-lib disabled.
 */
#include "internal/deprecated.h"
#include "internal/sdf.h"

void ossl_sdf_lib_cleanup(void)
{
    /* no-op when SDF is disabled */
}
