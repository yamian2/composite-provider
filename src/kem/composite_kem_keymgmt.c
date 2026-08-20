#include "composite_kem_keymgmt.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <string.h>

typedef struct {
    COMPOSITE_CTX *provctx;
} COMPOSITE_KEM_GEN_CTX;

typedef struct {
    const char *name;
    int security_bits;
} COMPOSITE_KEM_SECURITY;

static const COMPOSITE_KEM_SECURITY kem_security[] = {
    { MLKEM768_RSA2048_SN, 112 },
    { MLKEM768_RSA3072_SN, 128 },
    { MLKEM768_RSA4096_SN, 152 },
    { MLKEM768_X25519_SN, 128 },
    { MLKEM768_P256_SN, 128 },
    { MLKEM768_P384_SN, 192 },
    { MLKEM768_BRAINPOOLP256_SN, 128 },
    { MLKEM1024_RSA3072_SN, 128 },
    { MLKEM1024_P384_SN, 192 },
    { MLKEM1024_BRAINPOOLP384_SN, 192 },
    { MLKEM1024_X448_SN, 224 },
    { MLKEM1024_P521_SN, 256 },
};

static int kem_security_bits(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(kem_security) / sizeof(kem_security[0]); i++) {
        if (strcmp(kem_security[i].name, name) == 0)
            return kem_security[i].security_bits;
    }
    return 0;
}

static void *kem_key_new(COMPOSITE_CTX *provctx, const char *name)
{
    COMPOSITE_KEM_KEY *key = composite_kemkey_new();

    if (key != NULL) {
        key->provctx = provctx;
        key->composite_name = name;
    }
    return key;
}

static void *kem_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    COMPOSITE_KEM_GEN_CTX *ctx;

    (void)params;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->provctx = (COMPOSITE_CTX *)provctx;
    return ctx;
}

static void kem_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static int kem_has(const void *keydata, int selection)
{
    const COMPOSITE_KEM_KEY *key = (const COMPOSITE_KEM_KEY *)keydata;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && (key->mlkem_pubkey == NULL || key->classic_pubkey == NULL))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_private)
        return 0;
    return 1;
}

static int kem_validate(const void *keydata, int selection, int checktype)
{
    (void)checktype;
    return kem_has(keydata, selection);
}

static int kem_match(const void *keydata1, const void *keydata2, int selection)
{
    const COMPOSITE_KEM_KEY *key1 = keydata1;
    const COMPOSITE_KEM_KEY *key2 = keydata2;

    if (key1 == NULL || key2 == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!kem_has(key1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
                || !kem_has(key2, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
            return 0;
        return EVP_PKEY_eq((EVP_PKEY *)key1->mlkem_pubkey,
                           (EVP_PKEY *)key2->mlkem_pubkey) == 1
            && EVP_PKEY_eq((EVP_PKEY *)key1->classic_pubkey,
                           (EVP_PKEY *)key2->classic_pubkey) == 1;
    }
    return 1;
}

static const OSSL_PARAM kem_gettable_params_list[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kem_gettable_params(void *provctx)
{
    (void)provctx;
    return kem_gettable_params_list;
}

static int kem_get_params(void *keydata, OSSL_PARAM params[])
{
    COMPOSITE_KEM_KEY *key = keydata;
    OSSL_PARAM *p;
    int bits;

    if (key == NULL || key->composite_name == NULL)
        return 0;

    bits = kem_security_bits(key->composite_name);
    if (bits == 0)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, bits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, bits))
        return 0;
    return 1;
}

/* =========================================================================
 * Import / export
 *
 * The wire form on both sides is the draft's raw concatenation: ek for the
 * public key (§4.1) and dk for the private key (§4.2).  Only those two
 * parameters are handled -- there is deliberately no per-component import,
 * because a composite key assembled from separately supplied ML-KEM and
 * traditional halves could pair components the composite OID does not name.
 * ========================================================================= */

static const OSSL_PARAM kem_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kem_import_types(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 ? kem_key_types : NULL;
}

static const OSSL_PARAM *kem_export_types(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 ? kem_key_types : NULL;
}

static int kem_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    COMPOSITE_KEM_KEY *key = keydata;
    const OSSL_PARAM *p;

    if (key == NULL || params == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    /*
     * Private first: dk carries the traditional private component, from which
     * OpenSSL derives the matching public half, so importing it populates both
     * slots.  Doing it the other way round would let a public-key import
     * silently discard the private material.
     */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING)
                return 0;
            return composite_kemkey_import_private(key, p->data, p->data_size);
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING)
                return 0;
            return composite_kemkey_import_public(key, p->data, p->data_size);
        }
    }

    ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                   "composite KEM import requires \"%s\" or \"%s\"",
                   OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY);
    return 0;
}

/*
 * Accept a key reference from this provider's own decoders
 * (OSSL_OBJECT_PARAM_REFERENCE hand-off).  The reference is a pointer to a
 * COMPOSITE_KEM_KEY pointer; ownership transfers to the caller.
 */
static void *kem_load(const void *reference, size_t reference_sz)
{
    if (reference == NULL || reference_sz != sizeof(COMPOSITE_KEM_KEY *))
        return NULL;
    return *(COMPOSITE_KEM_KEY * const *)reference;
}

static int kem_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_cb, void *cbarg)
{
    COMPOSITE_KEM_KEY *key = keydata;
    OSSL_PARAM params[3];
    size_t n = 0;
    unsigned char *pub = NULL, *priv = NULL;
    size_t pub_len = 0, priv_len = 0;
    int ret = 0;

    if (key == NULL || param_cb == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!composite_kemkey_encode_public(key, &pub, &pub_len))
            goto done;
        params[n++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        if (!composite_kemkey_encode_private(key, &priv, &priv_len))
            goto done;
        params[n++] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len);
    }
    if (n == 0)
        goto done;

    params[n] = OSSL_PARAM_construct_end();
    ret = param_cb(params, cbarg);

done:
    /*
     * The callback has either copied what it needs or failed; either way the
     * seed and traditional private scalar must not outlive this frame.
     */
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pub);
    return ret;
}

#define KEM_KEYMGMT(name, sn)                                                   \
    static void *name##_new(void *provctx)                                      \
    { return kem_key_new((COMPOSITE_CTX *)provctx, sn); }                       \
    static void *name##_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)       \
    {                                                                           \
        COMPOSITE_KEM_GEN_CTX *ctx = genctx;                                    \
        COMPOSITE_KEM_KEY *key;                                                 \
        (void)cb; (void)cbarg;                                                  \
        if (ctx == NULL)                                                        \
            return NULL;                                                        \
        key = kem_key_new(ctx->provctx, sn);                                    \
        if (key == NULL || !composite_kemkey_generate(key, sn, ctx->provctx)) { \
            composite_kemkey_free(key);                                         \
            return NULL;                                                        \
        }                                                                       \
        return key;                                                             \
    }                                                                           \
    const OSSL_DISPATCH name##_functions[] = {                                  \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))name##_new },                  \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))composite_kemkey_free },      \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kem_has },                     \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kem_match },                 \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))kem_validate },           \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kem_get_params },       \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
          (void (*)(void))kem_gettable_params },                                \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))kem_gen_init },           \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))name##_gen },                  \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kem_gen_cleanup },     \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kem_load },                   \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kem_import },               \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kem_import_types },   \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kem_export },               \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kem_export_types },   \
        OSSL_DISPATCH_END                                                       \
    }

KEM_KEYMGMT(mlkem768_rsa2048, MLKEM768_RSA2048_SN);
KEM_KEYMGMT(mlkem768_rsa3072, MLKEM768_RSA3072_SN);
KEM_KEYMGMT(mlkem768_rsa4096, MLKEM768_RSA4096_SN);
KEM_KEYMGMT(mlkem768_x25519, MLKEM768_X25519_SN);
KEM_KEYMGMT(mlkem768_p256, MLKEM768_P256_SN);
KEM_KEYMGMT(mlkem768_p384, MLKEM768_P384_SN);
KEM_KEYMGMT(mlkem768_brainpoolp256, MLKEM768_BRAINPOOLP256_SN);
KEM_KEYMGMT(mlkem1024_rsa3072, MLKEM1024_RSA3072_SN);
KEM_KEYMGMT(mlkem1024_p384, MLKEM1024_P384_SN);
KEM_KEYMGMT(mlkem1024_brainpoolp384, MLKEM1024_BRAINPOOLP384_SN);
KEM_KEYMGMT(mlkem1024_x448, MLKEM1024_X448_SN);
KEM_KEYMGMT(mlkem1024_p521, MLKEM1024_P521_SN);

#define KEM_NAMES(ln, sn, oid) ln ":" sn ":" oid

const OSSL_ALGORITHM *composite_kem_keymgmt_algorithms(void *provctx)
{
    static const OSSL_ALGORITHM algorithms[] = {
        { KEM_NAMES(MLKEM768_RSA2048_LN, MLKEM768_RSA2048_SN, MLKEM768_RSA2048_OID),
          "provider=composite", mlkem768_rsa2048_functions, NULL },
        { KEM_NAMES(MLKEM768_RSA3072_LN, MLKEM768_RSA3072_SN, MLKEM768_RSA3072_OID),
          "provider=composite", mlkem768_rsa3072_functions, NULL },
        { KEM_NAMES(MLKEM768_RSA4096_LN, MLKEM768_RSA4096_SN, MLKEM768_RSA4096_OID),
          "provider=composite", mlkem768_rsa4096_functions, NULL },
        { KEM_NAMES(MLKEM768_X25519_LN, MLKEM768_X25519_SN, MLKEM768_X25519_OID),
          "provider=composite", mlkem768_x25519_functions, NULL },
        { KEM_NAMES(MLKEM768_P256_LN, MLKEM768_P256_SN, MLKEM768_P256_OID),
          "provider=composite", mlkem768_p256_functions, NULL },
        { KEM_NAMES(MLKEM768_P384_LN, MLKEM768_P384_SN, MLKEM768_P384_OID),
          "provider=composite", mlkem768_p384_functions, NULL },
        { KEM_NAMES(MLKEM768_BRAINPOOLP256_LN, MLKEM768_BRAINPOOLP256_SN, MLKEM768_BRAINPOOLP256_OID),
          "provider=composite", mlkem768_brainpoolp256_functions, NULL },
        { KEM_NAMES(MLKEM1024_RSA3072_LN, MLKEM1024_RSA3072_SN, MLKEM1024_RSA3072_OID),
          "provider=composite", mlkem1024_rsa3072_functions, NULL },
        { KEM_NAMES(MLKEM1024_P384_LN, MLKEM1024_P384_SN, MLKEM1024_P384_OID),
          "provider=composite", mlkem1024_p384_functions, NULL },
        { KEM_NAMES(MLKEM1024_BRAINPOOLP384_LN, MLKEM1024_BRAINPOOLP384_SN, MLKEM1024_BRAINPOOLP384_OID),
          "provider=composite", mlkem1024_brainpoolp384_functions, NULL },
        { KEM_NAMES(MLKEM1024_X448_LN, MLKEM1024_X448_SN, MLKEM1024_X448_OID),
          "provider=composite", mlkem1024_x448_functions, NULL },
        { KEM_NAMES(MLKEM1024_P521_LN, MLKEM1024_P521_SN, MLKEM1024_P521_OID),
          "provider=composite", mlkem1024_p521_functions, NULL },
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    return algorithms;
}
