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
# include <openssl/types.h>
# include <openssl/pem.h>
# include <openssl/zkpbperr.h>

# ifndef OPENSSL_NO_BULLETPROOFS
# ifdef  __cplusplus
extern "C" {
# endif

# define PEM_STRING_BULLETPROOFS_PUB_PARAM      "BULLETPROOFS PUBLIC PARAM"
# define PEM_STRING_BULLETPROOFS_RANGE_PROOF    "BULLETPROOFS RANGE PROOF"
# define PEM_STRING_BULLETPROOFS_R1CS_PROOF     "BULLETPROOFS R1CS PROOF"

# define BULLET_PROOF_MAX_GENS_CAPACITY         128
# define BULLET_PROOF_MAX_PARTY_CAPACITY        64

typedef struct bp_pub_param_st           BP_PUB_PARAM;

typedef struct bp_transcript_method_st   BP_TRANSCRIPT_METHOD;
typedef struct bp_transcript_st          BP_TRANSCRIPT;

typedef struct bp_range_ctx_st           BP_RANGE_CTX;
typedef struct bp_range_witness_st       BP_RANGE_WITNESS;
typedef struct bp_range_proof_st         BP_RANGE_PROOF;

typedef struct bp_r1cs_ctx_st            BP_R1CS_CTX;
typedef struct bp_r1cs_witness_st        BP_R1CS_WITNESS;
typedef struct bp_r1cs_proof_st          BP_R1CS_PROOF;

typedef struct bp_r1cs_variable_st                  BP_R1CS_VARIABLE;
typedef struct bp_r1cs_linear_combination_item_st   BP_R1CS_LINEAR_COMBINATION_ITEM;
typedef BP_R1CS_LINEAR_COMBINATION_ITEM             BP_R1CS_LC_ITEM;
typedef struct bp_r1cs_linear_combination_st        BP_R1CS_LINEAR_COMBINATION;
typedef BP_R1CS_LINEAR_COMBINATION                  BP_R1CS_LC;

typedef enum bp_r1cs_variable_type {
    BP_R1CS_VARIABLE_COMMITTED,
    BP_R1CS_VARIABLE_MULTIPLIER_LEFT,
    BP_R1CS_VARIABLE_MULTIPLIER_RIGHT,
    BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT,
    BP_R1CS_VARIABLE_ONE,
} BP_R1CS_VARIABLE_TYPE;

/********************************************************************/
/*         functions for doing bulletproofs arithmetic               */
/********************************************************************/

/** Creates a new BP_PUB_PARAM object
 *  \param  curve_id        the elliptic curve id
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated range proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new(int curve_id, int gens_capacity, int party_capacity);

/** Creates a new BP_PUB_PARAM object by curve name
 *  \param  curve_name    the elliptic curve name
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new_by_curve_name(const char *curve_name,
                                             int gens_capacity,
                                             int party_capacity);
/** Frees a BP_PUB_PARAM object
 *  \param  pp        BP_PUB_PARAM object to be freed
 */
void BP_PUB_PARAM_free(BP_PUB_PARAM *pp);

/** Increases the internal reference count of a BP_PUB_PARAM object.
 *  \param  pp  BP_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_PUB_PARAM_up_ref(BP_PUB_PARAM *pp);

/** Decreases the internal reference count of a BP_PUB_PARAM object.
 *  \param  pp  BP_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_PUB_PARAM_down_ref(BP_PUB_PARAM *pp);

/********************************************************************/
/*         functions for doing range proof arithmetic                */
/********************************************************************/

/** Creates a new BP_RANGE_CTX object
 *  \return newly created BP_RANGE_CTX object or NULL in case of an error
 */
BP_RANGE_CTX *BP_RANGE_CTX_new(BP_PUB_PARAM *pp, BP_TRANSCRIPT *transcript);

/** Frees a BP_RANGE_CTX object
 *  \param  ctx       BP_RANGE_CTX object to be freed
 */
void BP_RANGE_CTX_free(BP_RANGE_CTX *ctx);

/** Creates a new BP_RANGE_WITNESS object
 *  \param  ctx       BP_RANGE_CTX object
 *  \return newly created BP_RANGE_WITNESS object or NULL in case of an error
 */
BP_RANGE_WITNESS *BP_RANGE_WITNESS_new(BP_RANGE_CTX *ctx);

/** Frees a BP_RANGE_WITNESS object
 *  \param  witness   BP_RANGE_WITNESS object to be freed
 */
void BP_RANGE_WITNESS_free(BP_RANGE_WITNESS *witness);

int BP_RANGE_WITNESS_commit(BP_RANGE_CTX *ctx, BP_RANGE_WITNESS *witness, int64_t secret);

/** Creates a new BP_RANGE_PROOF object
 *  \param  ctx       BP_RANGE_CTX object
 *  \return newly created BP_RANGE_PROOF object or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new(BP_RANGE_CTX *ctx);

/** Frees a BP_RANGE_PROOF object
 *  \param  proof     BP_RANGE_PROOF object to be freed
 */
void BP_RANGE_PROOF_free(BP_RANGE_PROOF *proof);

/** Increases the internal reference count of a BP_RANGE_PROOF object.
 *  \param  proof  BP_RANGE_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_RANGE_PROOF_up_ref(BP_RANGE_PROOF *proof);

/** Decreases the internal reference count of a BP_RANGE_PROOF object.
 *  \param  proof  BP_RANGE_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_RANGE_PROOF_down_ref(BP_RANGE_PROOF *proof);

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  witness   BP_RANGE_WITNESS object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BP_RANGE_PROOF_prove(BP_RANGE_CTX *ctx, BP_RANGE_WITNESS *witness,
                         BP_RANGE_PROOF *proof);

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  witness   BP_RANGE_WITNESS object
 *  \return BP_RANGE_PROOF object on success or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_prove_new(BP_RANGE_CTX *ctx,
                                         BP_RANGE_WITNESS *witness);

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  witness   BP_RANGE_WITNESS object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BP_RANGE_PROOF_verify(BP_RANGE_CTX *ctx, BP_RANGE_WITNESS *witness,
                          BP_RANGE_PROOF *proof);

/** Encodes BP_PUB_PARAM to binary
 *  \param  pp         BP_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_PUB_PARAM_encode(const BP_PUB_PARAM *pp, unsigned char *out, size_t size);

/** Encodes BP_RANGE_WITNESS to binary
 *  \param  pp         BP_RANGE_WITNESS object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_RANGE_WITNESS_encode(const BP_RANGE_WITNESS *witness,
                               unsigned char *out, size_t size);

/** Decodes binary to BP_RANGE_WITNESS
 *  \param  in         Memory buffer with the encoded BP_RANGE_WITNESS
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_RANGE_WITNESS object pointer on success and NULL otherwise
 */
BP_RANGE_WITNESS *BP_RANGE_WITNESS_decode(const unsigned char *in, size_t size);

/** Decodes binary to BP_PUB_PARAM
 *  \param  in         Memory buffer with the encoded BP_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_PUB_PARAM object pointer on success and NULL otherwise
 */
BP_PUB_PARAM *BP_PUB_PARAM_decode(const unsigned char *in, size_t size);

/** Encodes BP_RANGE_PROOF to binary
 *  \param  proof      BP_RANGE_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_RANGE_PROOF_encode(const BP_RANGE_PROOF *proof, unsigned char *out,
                             size_t size);

/** Decodes binary to BP_RANGE_PROOF
 *  \param  in         Memory buffer with the encoded BP_RANGE_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_RANGE_PROOF_PUB_PARAM object pointer on success and NULL otherwise
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_decode(const unsigned char *in, size_t size);

/********************************************************************/
/*         functions for doing r1cs arithmetic                      */
/********************************************************************/

BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_TYPE type,
                                       uint64_t value, const EC_POINT *C);
BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_dup(const BP_R1CS_VARIABLE *var);
void BP_R1CS_VARIABLE_free(BP_R1CS_VARIABLE *var);
BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_new(BP_R1CS_VARIABLE *var, const BIGNUM *scalar);
BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_dup(BP_R1CS_LC_ITEM *item);
void BP_R1CS_LC_ITEM_free(BP_R1CS_LC_ITEM *item);

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new(void);
BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new_from_param(BP_R1CS_VARIABLE *var,
                                                                      const BIGNUM *scalar);
BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_dup(const BP_R1CS_LINEAR_COMBINATION *lc);
void BP_R1CS_LINEAR_COMBINATION_free(BP_R1CS_LINEAR_COMBINATION *lc);

int BP_R1CS_LINEAR_COMBINATION_mul(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *out,
                                   const BP_R1CS_LINEAR_COMBINATION *left,
                                   const BP_R1CS_LINEAR_COMBINATION *right);
int BP_R1CS_LINEAR_COMBINATION_add(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *out,
                                   const BP_R1CS_LINEAR_COMBINATION *left,
                                   const BP_R1CS_LINEAR_COMBINATION *right);
int BP_R1CS_LINEAR_COMBINATION_sub(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *out,
                                   const BP_R1CS_LINEAR_COMBINATION *left,
                                   const BP_R1CS_LINEAR_COMBINATION *right);
int BP_R1CS_LINEAR_COMBINATION_neg(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *lc);
int BP_R1CS_LINEAR_COMBINATION_mul_bn(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value);
int BP_R1CS_LINEAR_COMBINATION_add_bn(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value);
int BP_R1CS_LINEAR_COMBINATION_eval(BP_R1CS_CTX *ctx,
                                    const BP_R1CS_LINEAR_COMBINATION *lc,
                                    BIGNUM *r, BN_CTX *bn_ctx);

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_bn_commit(BP_R1CS_CTX *ctx, BIGNUM *value);
BP_R1CS_LINEAR_COMBINATION *BP_R1CS_lc_commit(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *lc);
int BP_R1CS_constrain(BP_R1CS_CTX *ctx, BP_R1CS_LINEAR_COMBINATION *lc);

BP_R1CS_PROOF *BP_R1CS_PROOF_new(BP_R1CS_CTX *ctx);
void BP_R1CS_PROOF_free(BP_R1CS_PROOF *proof);
BP_R1CS_PROOF *BP_R1CS_prove(BP_R1CS_CTX *ctx);
int BP_R1CS_verify(BP_R1CS_CTX *ctx, BP_R1CS_PROOF *proof);

BP_R1CS_CTX *BP_R1CS_CTX_new(BP_PUB_PARAM *pp, BP_TRANSCRIPT *transcript);
void BP_R1CS_CTX_free(BP_R1CS_CTX *ctx);

# ifndef OPENSSL_NO_STDIO
int BP_PUB_PARAM_print_fp(FILE *fp, const BP_PUB_PARAM *pp, int indent);
int BP_RANGE_PROOF_print_fp(FILE *fp, const BP_RANGE_PROOF *proof, int indent);
# endif
int BP_PUB_PARAM_print(BIO *bp, const BP_PUB_PARAM *pp, int indent);
int BP_RANGE_PROOF_print(BIO *bp, const BP_RANGE_PROOF *proof, int indent);

DECLARE_PEM_rw(BULLETPROOFS_PublicParam, BP_PUB_PARAM)
DECLARE_PEM_rw(BULLETPROOFS_RangeProof, BP_RANGE_PROOF)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_PUB_PARAM, BP_PUB_PARAM)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_RANGE_PROOF, BP_RANGE_PROOF)

BP_TRANSCRIPT *BP_TRANSCRIPT_new(const BP_TRANSCRIPT_METHOD *method,
                                 const char *label);
BP_TRANSCRIPT *BP_TRANSCRIPT_dup(const BP_TRANSCRIPT *src);
void BP_TRANSCRIPT_free(BP_TRANSCRIPT *transcript);
int BP_TRANSCRIPT_reset(BP_TRANSCRIPT *transcript);
const BP_TRANSCRIPT_METHOD *BP_TRANSCRIPT_METHOD_sha256(void);

# ifdef  __cplusplus
}
# endif
# endif

#endif
