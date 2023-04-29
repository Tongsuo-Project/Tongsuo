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

# define BULLET_PROOF_MAX_BITS          256
# define BULLET_PROOF_MAX_AGG_NUM       32

typedef struct bullet_proof_pub_param_st BULLET_PROOF_PUB_PARAM;
typedef struct bp_range_proof_ctx_st BP_RANGE_PROOF_CTX;
typedef struct bp_range_proof_witness_st BP_RANGE_PROOF_WITNESS;
typedef struct bp_range_proof_st BP_RANGE_PROOF;

typedef struct bp_transcript_method_st BP_TRANSCRIPT_METHOD;
typedef struct bp_transcript_st        BP_TRANSCRIPT;

/** Creates a new BULLET_PROOF_PUB_PARAM object
 *  \param  curve_id    the elliptic curve id
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new(int curve_id, int bits,
                                                   int max_agg_num);

/** Creates a new BULLET_PROOF_PUB_PARAM object by curve name
 *  \param  curve_name    the elliptic curve name
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new_by_curve_name(const char *curve_name,
                                                                 int bits,
                                                                 int max_agg_num);
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

/** Creates a new BP_RANGE_PROOF_CTX object
 *  \return newly created BP_RANGE_PROOF_CTX object or NULL in case of an error
 */
BP_RANGE_PROOF_CTX *BP_RANGE_PROOF_CTX_new(BULLET_PROOF_PUB_PARAM *pp,
                                           BP_TRANSCRIPT *transcript);

/** Frees a BP_RANGE_PROOF_CTX object
 *  \param  ctx       BP_RANGE_PROOF_CTX object to be freed
 */
void BP_RANGE_PROOF_CTX_free(BP_RANGE_PROOF_CTX *ctx);

/** Creates a new BP_RANGE_PROOF_WITNESS object
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  secrets   An array of secrets used to generate the witness
 *  \param  len       the length of secrets
 *  \return newly created BP_RANGE_PROOF_WITNESS object or NULL in case of an error
 */
BP_RANGE_PROOF_WITNESS *BP_RANGE_PROOF_WITNESS_new(BP_RANGE_PROOF_CTX *ctx,
                                               int64_t secrets[], int len);

/** Frees a BP_RANGE_PROOF_WITNESS object
 *  \param  witness   BP_RANGE_PROOF_WITNESS object to be freed
 */
void BP_RANGE_PROOF_WITNESS_free(BP_RANGE_PROOF_WITNESS *witness);

/** Creates a new BP_RANGE_PROOF object
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \return newly created BP_RANGE_PROOF_CTX object or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new(BP_RANGE_PROOF_CTX *ctx);

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
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  witness   BP_RANGE_PROOF_WITNESS object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BP_RANGE_PROOF_prove(BP_RANGE_PROOF_CTX *ctx, BP_RANGE_PROOF_WITNESS *witness,
                         BP_RANGE_PROOF *proof);

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BP_RANGE_PROOF_verify(BP_RANGE_PROOF_CTX *ctx, BP_RANGE_PROOF *proof);

/** Encodes BP_RANGE_PROOF_PUB_PARAM to binary
 *  \param  pp         BP_RANGE_PROOF_PUB_PARAM object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t BULLET_PROOF_PUB_PARAM_encode(const BULLET_PROOF_PUB_PARAM *pp,
                                     unsigned char *out, size_t size);

/** Decodes binary to BULLET_PROOF_PUB_PARAM
 *  \param  in         Memory buffer with the encoded BULLET_PROOF_PUB_PARAM
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return BULLET_PROOF_PUB_PARAM object pointer on success and NULL otherwise
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_decode(const unsigned char *in,
                                                      size_t size);

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

# ifndef OPENSSL_NO_STDIO
int BULLET_PROOF_PUB_PARAM_print_fp(FILE *fp, const BULLET_PROOF_PUB_PARAM *pp,
                                    int indent);
int BP_RANGE_PROOF_print_fp(FILE *fp, const BP_RANGE_PROOF *proof, int indent);
# endif
int BULLET_PROOF_PUB_PARAM_print(BIO *bp, const BULLET_PROOF_PUB_PARAM *pp,
                                 int indent);
int BP_RANGE_PROOF_print(BIO *bp, const BP_RANGE_PROOF *proof, int indent);

DECLARE_PEM_rw(BULLETPROOFS_PublicParam, BULLET_PROOF_PUB_PARAM)
DECLARE_PEM_rw(BULLETPROOFS_RangeProof, BP_RANGE_PROOF)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(BULLET_PROOF_PUB_PARAM, BULLET_PROOF_PUB_PARAM)
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
