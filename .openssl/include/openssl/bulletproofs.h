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
# include <openssl/zkp_transcript.h>
# include <openssl/zkpbperr.h>

# ifndef OPENSSL_NO_BULLETPROOFS
#  ifdef  __cplusplus
extern "C" {
#  endif

# define PEM_STRING_BULLETPROOFS_PUB_PARAM      "BULLETPROOFS PUBLIC PARAM"
# define PEM_STRING_BULLETPROOFS_WITNESS        "BULLETPROOFS WITNESS"
# define PEM_STRING_BULLETPROOFS_RANGE_PROOF    "BULLETPROOFS RANGE PROOF"
# define PEM_STRING_BULLETPROOFS_R1CS_PROOF     "BULLETPROOFS R1CS PROOF"

# define BULLET_PROOF_MAX_GENS_CAPACITY         128
# define BULLET_PROOF_MAX_PARTY_CAPACITY        64

typedef struct bp_pub_param_st           BP_PUB_PARAM;
typedef struct bp_witness_st             BP_WITNESS;
typedef struct bp_variable_st            BP_VARIABLE;

typedef struct bp_range_ctx_st           BP_RANGE_CTX;
typedef struct bp_range_proof_st         BP_RANGE_PROOF;

typedef struct bp_r1cs_ctx_st            BP_R1CS_CTX;
typedef struct bp_r1cs_proof_st          BP_R1CS_PROOF;

typedef struct bp_r1cs_variable_st                  BP_R1CS_VARIABLE;
typedef struct bp_r1cs_linear_combination_item_st   BP_R1CS_LINEAR_COMBINATION_ITEM;
typedef BP_R1CS_LINEAR_COMBINATION_ITEM             BP_R1CS_LC_ITEM;
typedef struct bp_r1cs_linear_combination_st        BP_R1CS_LINEAR_COMBINATION;
typedef BP_R1CS_LINEAR_COMBINATION                  BP_R1CS_LC;

/********************************************************************/
/*         functions for doing bulletproofs arithmetic               */
/********************************************************************/

/** Creates a new BP_PUB_PARAM object
 *  \param  group           underlying EC_GROUP object
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new(const EC_GROUP *group, int gens_capacity,
                               int party_capacity);

/** Creates a new BP_PUB_PARAM object by curve name
 *  \param  curve_name      the elliptic curve name
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

/** Creates a new BP_PUB_PARAM object by curve id
 *  \param  curve_id        the elliptic curve id
 *  \param  gens_capacity   the number of generators to precompute for each party.
 *                          For range_proof, it is the maximum bitsize of the
 *                          range_proof, maximum value is 64. For r1cs_proof,
 *                          the capacity must be greater than the number of
 *                          multipliers, rounded up to the next power of two.
 *  \param  party_capacity  the maximum number of parties that can produce on
 *                          aggregated proof. For r1cs_proof, set to 1.
 *  \return newly created BP_PUB_PARAM object or NULL in case of an error
 */
BP_PUB_PARAM *BP_PUB_PARAM_new_by_curve_id(int curve_id,
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

/** Creates a new BP_VARIABLE object
 *  \param  name           the bulletproofs variable name, used for indexing.
 *  \param  point          EC_POINT object
 *  \param  group          EC_GROUP object
 *  \return newly created BP_WITNESS object or NULL in case of an error
 */
BP_VARIABLE *BP_VARIABLE_new(const char *name, const EC_POINT *point, const EC_GROUP *group);

/** Frees a BP_VARIABLE object
 *  \param  var   BP_VARIABLE object to be freed
 */
void BP_VARIABLE_free(BP_VARIABLE *var);

/** Creates a new BP_WITNESS object
 *  \param  pp           underlying BP_PUB_PARAM object
 *  \return newly created BP_WITNESS object or NULL in case of an error
 */
BP_WITNESS *BP_WITNESS_new(const BP_PUB_PARAM *pp);

/** Frees a BP_WITNESS object
 *  \param  witness   BP_WITNESS object to be freed
 */
void BP_WITNESS_free(BP_WITNESS *witness);

/** Increases the internal reference count of a BP_WITNESS object.
 *  \param  witness  BP_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_WITNESS_up_ref(BP_WITNESS *witness);

/** Decreases the internal reference count of a BP_WITNESS object.
 *  \param  witness  BP_WITNESS object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_WITNESS_down_ref(BP_WITNESS *witness);

/** Commit v to the witness and calculate V=G^r*H^v
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name used to index the BP_VARIABLE object
 *  \param  v         plaintext BIGNUM object
 *  \return 1 on success and 0 otherwise
 */
int BP_WITNESS_commit(BP_WITNESS *witness, const char *name, const BIGNUM *v);

/** Get the BP_VARIABLE with the variable name from the witness.
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name of the BP_VARIABLE object
 *  \return the BP_VARIABLE object when found by name, otherwise return NULL.
 */
BP_VARIABLE *BP_WITNESS_get_variable(BP_WITNESS *witness, const char *name);

/** Get the index of the BP_VARIABLE in the stack that corresponds to the variable
 *  name from the witness.
 *  \param  witness   BP_WITNESS object
 *  \param  name      the name of the BP_VARIABLE object
 *  \return the index of the BP_VARIABLE object when found by name,
 *  otherwise return -1.
 */
int BP_WITNESS_get_variable_index(BP_WITNESS *witness, const char *name);

/********************************************************************/
/*         functions for doing range proof arithmetic                */
/********************************************************************/

/** Creates a new BP_RANGE_CTX object
 *  \param  pp          BP_PUB_PARAM object
 *  \param  witness     BP_WITNESS object
 *  \param  transcript  ZKP_TRANSCRIPT object
 *  \return newly created BP_RANGE_CTX object or NULL in case of an error
 */
BP_RANGE_CTX *BP_RANGE_CTX_new(BP_PUB_PARAM *pp, BP_WITNESS *witness,
                               ZKP_TRANSCRIPT *transcript);

/** Frees a BP_RANGE_CTX object
 *  \param  ctx       BP_RANGE_CTX object to be freed
 */
void BP_RANGE_CTX_free(BP_RANGE_CTX *ctx);

/** Creates a new BP_RANGE_PROOF object
 *  \param  pp          BP_PUB_PARAM object
 *  \return newly created BP_RANGE_PROOF object or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new(const BP_PUB_PARAM *pp);

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
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BP_RANGE_PROOF_prove(BP_RANGE_CTX *ctx, BP_RANGE_PROOF *proof);

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BP_RANGE_CTX object
 *  \return the BP_RANGE_PROOF object on success or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new_prove(BP_RANGE_CTX *ctx);

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BP_RANGE_PROOF_verify(BP_RANGE_CTX *ctx, const BP_RANGE_PROOF *proof);

/** Encodes BP_PUB_PARAM to binary
 *  \param  pp         BP_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_PUB_PARAM_encode(const BP_PUB_PARAM *pp, unsigned char *out, size_t size);

/** Encodes BP_WITNESS to binary
 *  \param  witness    BP_WITNESS object
 *  \param  out        The buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  flag       The flag is an indicator for encoding random number 'r'
 *                     and plaintext 'v', with 1 indicating encoding and 0
 *                     indicating no encoding.
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_WITNESS_encode(const BP_WITNESS *witness, unsigned char *out,
                         size_t size, int flag);

/** Decodes binary to BP_WITNESS
 *  \param  in         Memory buffer with the encoded BP_WITNESS
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \param  flag       The flag is an indicator for decoding random number 'r'
 *                     and plaintext 'v', with 1 indicating decoding and 0
 *  \return BP_WITNESS object pointer on success and NULL otherwise
 */
BP_WITNESS *BP_WITNESS_decode(const unsigned char *in, size_t size, int flag);

/** Decodes binary to BP_PUB_PARAM
 *  \param  in         Memory buffer with the encoded BP_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return the BP_PUB_PARAM object pointer on success and NULL otherwise
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
 *  \return BP_RANGE_PROOF object pointer on success and NULL otherwise
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_decode(const unsigned char *in, size_t size);

/** Encodes BP_R1CS_PROOF to binary
 *  \param  proof      BP_R1CS_PROOF object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BP_R1CS_PROOF_encode(const BP_R1CS_PROOF *proof, unsigned char *out,
                            size_t size);

/** Decodes binary to BP_R1CS_PROOF
 *  \param  in         Memory buffer with the encoded BP_R1CS_PROOF object
 *  \param  size       The memory size of the in pointer object
 *  \return BP_R1CS_PROOF object pointer on success and NULL otherwise
 */
BP_R1CS_PROOF *BP_R1CS_PROOF_decode(const unsigned char *in, size_t size);

/********************************************************************/
/*         functions for doing r1cs arithmetic                      */
/********************************************************************/

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new(void);
BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_dup(const BP_R1CS_LINEAR_COMBINATION *lc);
void BP_R1CS_LINEAR_COMBINATION_free(BP_R1CS_LINEAR_COMBINATION *lc);
int BP_R1CS_LINEAR_COMBINATION_clean(BP_R1CS_LINEAR_COMBINATION *lc);

int BP_R1CS_LINEAR_COMBINATION_raw_mul(BP_R1CS_LINEAR_COMBINATION **output,
                                       BP_R1CS_LINEAR_COMBINATION **left,
                                       BP_R1CS_LINEAR_COMBINATION **right,
                                       const BIGNUM *l, const BIGNUM *r,
                                       BP_R1CS_CTX *ctx);
int BP_R1CS_LINEAR_COMBINATION_mul(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other,
                                   BP_R1CS_CTX *ctx);
int BP_R1CS_LINEAR_COMBINATION_add(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other);
int BP_R1CS_LINEAR_COMBINATION_sub(BP_R1CS_LINEAR_COMBINATION *lc,
                                   const BP_R1CS_LINEAR_COMBINATION *other);
int BP_R1CS_LINEAR_COMBINATION_neg(BP_R1CS_LINEAR_COMBINATION *lc);
int BP_R1CS_LINEAR_COMBINATION_mul_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value);
int BP_R1CS_LINEAR_COMBINATION_add_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value);
int BP_R1CS_LINEAR_COMBINATION_sub_bn(BP_R1CS_LINEAR_COMBINATION *lc,
                                      const BIGNUM *value);

BP_R1CS_LINEAR_COMBINATION *BP_WITNESS_r1cs_linear_combination_commit(BP_WITNESS *witness,
                                                                      const char *name,
                                                                      BIGNUM *v);
BP_R1CS_LINEAR_COMBINATION *BP_WITNESS_r1cs_linear_combination_get(BP_WITNESS *witness,
                                                                   const char *name);
int BP_R1CS_LINEAR_COMBINATION_constrain(BP_R1CS_LINEAR_COMBINATION *lc, BP_R1CS_CTX *ctx);
int BP_WITNESS_r1cs_commit(BP_WITNESS *witness, const char *name, BIGNUM *v);
int BP_R1CS_constraint_expression(BP_R1CS_CTX *ctx, const char *constraint, int is_prove);

BP_R1CS_PROOF *BP_R1CS_PROOF_new(BP_R1CS_CTX *ctx);
void BP_R1CS_PROOF_free(BP_R1CS_PROOF *proof);
BP_R1CS_PROOF *BP_R1CS_PROOF_prove(BP_R1CS_CTX *ctx);
int BP_R1CS_PROOF_verify(BP_R1CS_CTX *ctx, BP_R1CS_PROOF *proof);

/** Creates a new BP_R1CS_CTX object
 *  \param  pp          BP_PUB_PARAM object
 *  \param  witness     BP_WITNESS object
 *  \param  transcript  ZKP_TRANSCRIPT object
 *  \return newly created BP_R1CS_CTX object or NULL in case of an error
 */
BP_R1CS_CTX *BP_R1CS_CTX_new(BP_PUB_PARAM *pp, BP_WITNESS *witness,
                             ZKP_TRANSCRIPT *transcript);

void BP_R1CS_CTX_free(BP_R1CS_CTX *ctx);

# ifndef OPENSSL_NO_STDIO
int BP_PUB_PARAM_print_fp(FILE *fp, const BP_PUB_PARAM *pp, int indent);
int BP_WITNESS_print_fp(FILE *fp, const BP_WITNESS *witness, int indent, int flag);
int BP_RANGE_PROOF_print_fp(FILE *fp, const BP_RANGE_PROOF *proof, int indent);
int BP_R1CS_PROOF_print_fp(FILE *fp, const BP_R1CS_PROOF *proof, int indent);
# endif
int BP_PUB_PARAM_print(BIO *bp, const BP_PUB_PARAM *pp, int indent);
int BP_WITNESS_print(BIO *bp, const BP_WITNESS *witness, int indent, int flag);
int BP_RANGE_PROOF_print(BIO *bp, const BP_RANGE_PROOF *proof, int indent);
int BP_R1CS_PROOF_print(BIO *bp, const BP_R1CS_PROOF *proof, int indent);

/********************************************************************/
/*         functions for doing bulletproofs encoding/decoding       */
/********************************************************************/

DECLARE_PEM_rw(BULLETPROOFS_PublicParam, BP_PUB_PARAM)
DECLARE_PEM_rw(BULLETPROOFS_LongWitness, BP_WITNESS)
DECLARE_PEM_rw(BULLETPROOFS_ShortWitness, BP_WITNESS)
DECLARE_PEM_rw(BULLETPROOFS_RangeProof, BP_RANGE_PROOF)
DECLARE_PEM_rw(BULLETPROOFS_R1CSProof, BP_R1CS_PROOF)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_PUB_PARAM, BP_PUB_PARAM)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_WITNESS, long_BP_WITNESS)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_WITNESS, short_BP_WITNESS)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_RANGE_PROOF, BP_RANGE_PROOF)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BP_R1CS_PROOF, BP_R1CS_PROOF)

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
