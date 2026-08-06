#ifndef _COMPOSITE_KEM_H
#define _COMPOSITE_KEM_H

#include "compat.h"
#include "composite_provider.h"
#include "composite_kem_info.h"
#include "provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

#include <string.h>
#include <stdlib.h>

/* KEM context structure */
typedef struct composite_kem_ctx_st {
    COMPOSITE_CTX *provctx;
    const char *algorithm_name;
    const COMPOSITE_KEM_ALG_INFO *alg_info;
    COMPOSITE_KEM_KEY *key;
} COMPOSITE_KEM_CTX;

void *composite_kem_newctx_base(void *provctx, const char *alg_sn);

#define DECLARE_KEM_DISPATCH_TABLE(alg_name) \
    const OSSL_DISPATCH composite_##alg_name##_kem_functions[];

#define EXTERN_DECLARE_KEM_DISPATCH_TABLE(alg_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_kem_functions[];

#define KEM_DISPATCH_TABLE(alg_name, sn_macro) \
    static void *composite_##alg_name##_kem_newctx(void *provctx) { \
        return composite_kem_newctx_base(provctx, sn_macro); \
    } \
    const OSSL_DISPATCH composite_##alg_name##_kem_functions[] = { \
        { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))composite_##alg_name##_kem_newctx }, \
        { OSSL_FUNC_KEM_FREECTX, (void (*)(void))composite_kem_freectx }, \
        { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))composite_kem_encapsulate_init }, \
        { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))composite_kem_encapsulate }, \
        { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))composite_kem_decapsulate_init }, \
        { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))composite_kem_decapsulate }, \
        { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))composite_kem_get_ctx_params }, \
        { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))composite_kem_gettable_ctx_params }, \
        { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))composite_kem_set_ctx_params }, \
        { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))composite_kem_settable_ctx_params }, \
        { 0, NULL } \
    };

#endif /* _COMPOSITE_KEM_H */
