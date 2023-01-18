/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BULLETPROOFS_H
# define HEADER_BULLETPROOFS_H

# include <stdlib.h>
# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/zkpbperr.h>

# ifndef OPENSSL_NO_BULLETPROOFS
# ifdef  __cplusplus
extern "C" {
# endif

# define BULLET_PROOF_MAX_BITS          64
# define BULLET_PROOF_MAX_AGG_NUM       32

typedef struct bullet_proof_pub_param_st BULLET_PROOF_PUB_PARAM;
typedef struct bullet_proof_ctx_st BULLET_PROOF_CTX;
typedef struct bullet_proof_witness_st BULLET_PROOF_WITNESS;
typedef struct bullet_proof_st BULLET_PROOF;

/** Creates a new BULLET_PROOF_PUB_PARAM object
 *  \param  curve_id    the elliptic curve id
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new(int curve_id, size_t bits,
                                                   size_t max_agg_num);

/** Frees a BULLET_PROOF_PUB_PARAM object
 *  \param  pp        BULLET_PROOF_PUB_PARAM object to be freed
 */
void BULLET_PROOF_PUB_PARAM_free(BULLET_PROOF_PUB_PARAM *pp);

/** Increases the internal reference count of a BULLET_PROOF_PUB_PARAM object.
 *  \param  pp  BULLET_PROOF_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_PUB_PARAM_up_ref(BULLET_PROOF_PUB_PARAM *pp);

/** Decreases the internal reference count of a BULLET_PROOF_PUB_PARAM object.
 *  \param  pp  BULLET_PROOF_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_PUB_PARAM_down_ref(BULLET_PROOF_PUB_PARAM *pp);

/** Creates a new BULLET_PROOF_CTX object
 *  \return newly created BULLET_PROOF_CTX object or NULL in case of an error
 */
BULLET_PROOF_CTX *BULLET_PROOF_CTX_new(BULLET_PROOF_PUB_PARAM *pp, const char *st);

/** Frees a BULLET_PROOF_CTX object
 *  \param  ctx       BULLET_PROOF_CTX object to be freed
 */
void BULLET_PROOF_CTX_free(BULLET_PROOF_CTX *ctx);

/** Creates a new BULLET_PROOF_WITNESS object
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  secrets   An array of secrets used to generate the witness
 *  \param  len       the length of secrets
 *  \return newly created BULLET_PROOF_WITNESS object or NULL in case of an error
 */
BULLET_PROOF_WITNESS *BULLET_PROOF_WITNESS_new(BULLET_PROOF_CTX *ctx,
                                               int64_t secrets[], size_t len);

/** Frees a BULLET_PROOF_WITNESS object
 *  \param  witness   BULLET_PROOF_WITNESS object to be freed
 */
void BULLET_PROOF_WITNESS_free(BULLET_PROOF_WITNESS *witness);

/** Creates a new BULLET_PROOF object
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \return newly created BULLET_PROOF_CTX object or NULL in case of an error
 */
BULLET_PROOF *BULLET_PROOF_new(BULLET_PROOF_CTX *ctx);

/** Frees a BULLET_PROOF object
 *  \param  proof     BULLET_PROOF object to be freed
 */
void BULLET_PROOF_free(BULLET_PROOF *proof);

/** Increases the internal reference count of a BULLET_PROOF object.
 *  \param  proof  BULLET_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_up_ref(BULLET_PROOF *proof);

/** Decreases the internal reference count of a BULLET_PROOF object.
 *  \param  proof  BULLET_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_down_ref(BULLET_PROOF *proof);

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  witness   BULLET_PROOF_WITNESS object
 *  \param  proof     BULLET_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BULLET_PROOF_prove(BULLET_PROOF_CTX *ctx, BULLET_PROOF_WITNESS *witness,
                       BULLET_PROOF *proof);

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  proof     BULLET_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BULLET_PROOF_verify(BULLET_PROOF_CTX *ctx, BULLET_PROOF *proof);

# ifdef  __cplusplus
}
# endif
# endif

#endif
