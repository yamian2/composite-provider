#include "composite_kem_key.h"
#include "composite_kem_info.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <string.h>

static EVP_PKEY *generate_key(COMPOSITE_CTX *ctx, const char *algorithm,
                              int parameter)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(ctx->libctx, algorithm, NULL);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0)
        goto done;

    if (strcmp(algorithm, DEFAULT_RSA_NAME) == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, parameter) <= 0)
            goto done;
    } else if (strcmp(algorithm, "EC") == 0) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, parameter) <= 0)
            goto done;
    }

    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

COMPOSITE_KEM_KEY *composite_kemkey_new(void)
{
    COMPOSITE_KEM_KEY *key = OPENSSL_malloc(sizeof(*key));

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memset(key, 0, sizeof(*key));
    return key;
}

int composite_kemkey_generate(COMPOSITE_KEM_KEY *key,
                              const char *algorithm,
                              COMPOSITE_CTX *ctx)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem_key = NULL;
    EVP_PKEY *classic_key = NULL;

    if (key == NULL || algorithm == NULL || ctx == NULL || ctx->libctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    alg = composite_kem_alg_info_find(algorithm);
    if (alg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    mlkem_key = generate_key(ctx, alg->mlkem_name, 0);
    if (mlkem_key == NULL) {
        /*
         * This is the point where a missing ML-KEM implementation actually
         * matters, so name it here rather than probing at provider-init time -
         * a probe there would bake provider load order into the answer.
         */
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "%s requires a loaded provider offering %s "
                       "(OpenSSL 3.5 or later)",
                       alg->composite_name, alg->mlkem_name);
        goto err;
    }

    classic_key = generate_key(ctx, alg->classic_name, alg->classic_param);
    if (classic_key == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "%s requires a loaded provider offering %s",
                       alg->composite_name, alg->classic_name);
        goto err;
    }

    if (!EVP_PKEY_up_ref(mlkem_key))
        goto err;
    if (!EVP_PKEY_up_ref(classic_key)) {
        EVP_PKEY_free(mlkem_key);
        goto err;
    }

    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);
    key->provctx = ctx;
    key->composite_name = alg->composite_name;
    key->mlkem_name = alg->mlkem_name;
    key->classic_algorithm_name = alg->classic_name;
    key->mlkem_pubkey = mlkem_key;
    key->mlkem_privkey = mlkem_key;
    key->classic_pubkey = classic_key;
    key->classic_privkey = classic_key;
    key->has_private = 1;
    return 1;

err:
    EVP_PKEY_free(mlkem_key);
    EVP_PKEY_free(classic_key);
    return 0;
}

void composite_kemkey_free(COMPOSITE_KEM_KEY *key)
{
    if (key == NULL)
        return;

    EVP_PKEY_CTX_free(key->ml_kem_ctx);
    EVP_PKEY_CTX_free(key->classic_ctx);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    OPENSSL_free(key);
}

int composite_kemkey_get0_components(const COMPOSITE_KEM_KEY *key,
                                     EVP_PKEY **ml_kem_key,
                                     EVP_PKEY **trad_key)
{
    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    *ml_kem_key = (EVP_PKEY *)key->mlkem_pubkey;
    *trad_key = (EVP_PKEY *)key->classic_pubkey;
    return 1;
}

int composite_kemkey_set0_components(COMPOSITE_KEM_KEY *key,
                                     EVP_PKEY *ml_kem_key,
                                     EVP_PKEY *trad_key)
{
    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * These are set0 semantics: the caller has already handed over its
     * reference, so on failure we own the keys and must release them - the
     * caller is documented not to.
     */
    if (!EVP_PKEY_up_ref(ml_kem_key)) {
        EVP_PKEY_free(ml_kem_key);
        EVP_PKEY_free(trad_key);
        return 0;
    }
    if (!EVP_PKEY_up_ref(trad_key)) {
        EVP_PKEY_free(ml_kem_key);  /* undo the up_ref above */
        EVP_PKEY_free(ml_kem_key);  /* release the transferred reference */
        EVP_PKEY_free(trad_key);
        return 0;
    }

    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);
    key->mlkem_pubkey = ml_kem_key;
    key->mlkem_privkey = ml_kem_key;
    key->classic_pubkey = trad_key;
    key->classic_privkey = trad_key;
    key->has_private = 1;
    return 1;
}

EVP_PKEY *composite_kemkey_get0_mlkem_public(const COMPOSITE_KEM_KEY *key)
{
    return key == NULL ? NULL : (EVP_PKEY *)key->mlkem_pubkey;
}

EVP_PKEY *composite_kemkey_get0_classic_public(const COMPOSITE_KEM_KEY *key)
{
    return key == NULL ? NULL : (EVP_PKEY *)key->classic_pubkey;
}

EVP_PKEY *composite_kemkey_get0_mlkem_private(const COMPOSITE_KEM_KEY *key)
{
    if (key == NULL)
        return NULL;
    return key->mlkem_privkey != NULL
        ? (EVP_PKEY *)key->mlkem_privkey
        : (EVP_PKEY *)key->mlkem_pubkey;
}

EVP_PKEY *composite_kemkey_get0_classic_private(const COMPOSITE_KEM_KEY *key)
{
    if (key == NULL)
        return NULL;
    return key->classic_privkey != NULL
        ? (EVP_PKEY *)key->classic_privkey
        : (EVP_PKEY *)key->classic_pubkey;
}
