#ifndef COMPOSITE_KEM_INFO_H
#define COMPOSITE_KEM_INFO_H

#include "composite_kem_key.h"

#include <openssl/types.h>
#include <stddef.h>

BEGIN_C_DECLS

typedef enum {
    COMP_KEM_TRAD_RSA_OAEP,
    COMP_KEM_TRAD_ECDH,
    COMP_KEM_TRAD_X25519,
    COMP_KEM_TRAD_X448
} COMPOSITE_KEM_TRAD_TYPE;

typedef struct {
    const char *composite_name;
    const char *mlkem_name;
    int mlkem_alg_id;
    size_t mlkem_ct_len;
    size_t mlkem_ss_len;
    const char *classic_name;
    COMPOSITE_KEM_TRAD_TYPE classic_type;
    int classic_param;
    size_t trad_ct_len;
    size_t final_ss_len;
    const unsigned char *label;
    size_t label_len;
} COMPOSITE_KEM_ALG_INFO;

const COMPOSITE_KEM_ALG_INFO *composite_kem_alg_info_find(
        const char *composite_name);

int composite_kem_combine_shared_secret(OSSL_LIB_CTX *libctx,
                                        const COMPOSITE_KEM_ALG_INFO *alg,
                                        const unsigned char *mlkem_ss,
                                        size_t mlkem_ss_len,
                                        const unsigned char *trad_ss,
                                        size_t trad_ss_len,
                                        const unsigned char *trad_ct,
                                        size_t trad_ct_len,
                                        const unsigned char *trad_pk,
                                        size_t trad_pk_len,
                                        unsigned char *out,
                                        size_t *out_len);

END_C_DECLS

#endif
