/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/obj_mac.h>
#include "internal/packet.h"
#include "prov/der_sm2_mldsa65_hybrid.h"

int ossl_DER_w_algorithmIdentifier_SM2_MLDSA65_HYBRID(WPACKET *pkt, int cont, SM2_MLDSA65_HYBRID_KEY *key)
{
    return ossl_DER_w_begin_sequence(pkt, cont)
        /* No parameters (yet?) */
        /* It seems SM2 identifier is the same as id_ecPublidKey */
        && ossl_DER_w_precompiled(pkt, -1, ossl_der_oid_id_MLDSA65_SM2_SM3,
                                  sizeof(ossl_der_oid_id_MLDSA65_SM2_SM3))
        && ossl_DER_w_end_sequence(pkt, cont);
}
