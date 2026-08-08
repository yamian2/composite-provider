#include "composite_kem_key.h"
#include "composite_kem_info.h"
#include "composite_kem_encoding.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <stdlib.h>
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

/* =========================================================================
 * Component key (de)serialization helpers
 * ========================================================================= */

static int kk_alloc_octets(size_t len, unsigned char **out, size_t *out_len)
{
    unsigned char *buf;

    if (out == NULL || out_len == NULL)
        return 0;

    buf = OPENSSL_malloc(len);
    if (buf == NULL)
        return 0;

    *out = buf;
    *out_len = len;
    return 1;
}

static size_t kk_mlkem_pub_size(int mlkem_alg_id)
{
    switch (mlkem_alg_id) {
    case ML_KEM_768:
        return ML_KEM_768_PUB_KEY_SZ;
    case ML_KEM_1024:
        return ML_KEM_1024_PUB_KEY_SZ;
    }
    return 0;
}

static int kk_serialize_raw_public(EVP_PKEY *pkey, size_t expected_len,
                                   unsigned char **out, size_t *out_len)
{
    size_t len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) <= 0)
        return 0;
    if (len != expected_len)
        return 0;
    if (!kk_alloc_octets(len, out, out_len))
        return 0;
    if (EVP_PKEY_get_raw_public_key(pkey, *out, &len) <= 0) {
        OPENSSL_free(*out);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    *out_len = len;
    return 1;
}

static int kk_serialize_encoded_public(EVP_PKEY *pkey, size_t expected_len,
                                       unsigned char **out, size_t *out_len)
{
    size_t len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        NULL, 0, &len) <= 0)
        return 0;
    if (expected_len != 0 && len != expected_len)
        return 0;
    if (!kk_alloc_octets(len, out, out_len))
        return 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        *out, len, &len) <= 0) {
        OPENSSL_free(*out);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    *out_len = len;
    return 1;
}

static int kk_serialize_rsa_public(EVP_PKEY *pkey, unsigned char **out,
                                   size_t *out_len)
{
    BIGNUM *n = NULL, *e = NULL;
    ASN1_INTEGER *asn1_n = NULL, *asn1_e = NULL;
    unsigned char *buf = NULL;
    unsigned char *p;
    int n_len, e_len, content_len, total_len;
    int ret = 0;

    if (out == NULL || out_len == NULL)
        return 0;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0
            || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) <= 0)
        goto done;

    asn1_n = BN_to_ASN1_INTEGER(n, NULL);
    asn1_e = BN_to_ASN1_INTEGER(e, NULL);
    if (asn1_n == NULL || asn1_e == NULL)
        goto done;

    n_len = i2d_ASN1_INTEGER(asn1_n, NULL);
    e_len = i2d_ASN1_INTEGER(asn1_e, NULL);
    if (n_len <= 0 || e_len <= 0)
        goto done;

    content_len = n_len + e_len;
    total_len = ASN1_object_size(1, content_len, V_ASN1_SEQUENCE);
    if (total_len <= 0)
        goto done;

    buf = OPENSSL_malloc((size_t)total_len);
    if (buf == NULL)
        goto done;

    p = buf;
    ASN1_put_object(&p, 1, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    if (i2d_ASN1_INTEGER(asn1_n, &p) <= 0
            || i2d_ASN1_INTEGER(asn1_e, &p) <= 0)
        goto done;

    *out = buf;
    *out_len = (size_t)total_len;
    buf = NULL;
    ret = 1;

done:
    OPENSSL_free(buf);
    ASN1_INTEGER_free(asn1_n);
    ASN1_INTEGER_free(asn1_e);
    BN_free(n);
    BN_free(e);
    return ret;
}

int composite_kemkey_serialize_trad_public(
        const struct composite_kem_alg_info_st *alg,
        EVP_PKEY *pkey, unsigned char **out, size_t *out_len)
{
    if (alg == NULL || pkey == NULL)
        return 0;

    switch (alg->classic_type) {
    case COMP_KEM_TRAD_RSA_OAEP:
        return kk_serialize_rsa_public(pkey, out, out_len);
    case COMP_KEM_TRAD_ECDH:
        return kk_serialize_encoded_public(pkey, alg->trad_ct_len, out, out_len);
    case COMP_KEM_TRAD_X25519:
        return kk_serialize_raw_public(pkey, 32, out, out_len);
    case COMP_KEM_TRAD_X448:
        return kk_serialize_raw_public(pkey, 56, out, out_len);
    }
    return 0;
}

/* =========================================================================
 * Component key constructors
 * ========================================================================= */

static EVP_PKEY *kk_mlkem_priv_from_seed(OSSL_LIB_CTX *libctx,
                                         const COMPOSITE_KEM_ALG_INFO *alg,
                                         const unsigned char *seed,
                                         size_t seed_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    if (seed_len != ML_KEM_768_PRIV_KEY_SZ) /* 64 for every parameter set */
        return NULL;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                                  (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(libctx, alg->mlkem_name, NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static EVP_PKEY *kk_mlkem_pub_from_raw(OSSL_LIB_CTX *libctx,
                                       const COMPOSITE_KEM_ALG_INFO *alg,
                                       const unsigned char *buf, size_t len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    if (len != kk_mlkem_pub_size(alg->mlkem_alg_id))
        return NULL;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)buf, len);
    params[1] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(libctx, alg->mlkem_name, NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Parse tradSK per draft §4.2 / Appendix B: a DER RSAPrivateKey (RFC 8017),
 * a DER ECPrivateKey (RFC 5915, publicKey field absent), or the raw
 * X25519/X448 scalar.  DER inputs must consume the whole buffer — trailing
 * bytes mean a corrupt or misaligned composite key.
 *
 * Deliberately no curve check here: check_classic_key_matches() at
 * *_init time is the enforcement point, so a mismatched-but-well-formed
 * key imports and is then rejected when used.
 */
static EVP_PKEY *kk_classic_priv_from_bytes(OSSL_LIB_CTX *libctx,
                                            const COMPOSITE_KEM_ALG_INFO *alg,
                                            const unsigned char *buf,
                                            size_t len)
{
    const unsigned char *p = buf;
    EVP_PKEY *pkey = NULL;

    switch (alg->classic_type) {
    case COMP_KEM_TRAD_RSA_OAEP:
        pkey = d2i_PrivateKey_ex(EVP_PKEY_RSA, NULL, &p, (long)len,
                                 libctx, NULL);
        break;
    case COMP_KEM_TRAD_ECDH:
        pkey = d2i_PrivateKey_ex(EVP_PKEY_EC, NULL, &p, (long)len,
                                 libctx, NULL);
        break;
    case COMP_KEM_TRAD_X25519:
        return len == 32
            ? EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL, buf, len)
            : NULL;
    case COMP_KEM_TRAD_X448:
        return len == 56
            ? EVP_PKEY_new_raw_private_key_ex(libctx, "X448", NULL, buf, len)
            : NULL;
    }

    if (pkey != NULL && p != buf + len) {
        EVP_PKEY_free(pkey);   /* trailing garbage after the DER structure */
        return NULL;
    }
    return pkey;
}

/* Parse a DER RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e } (RFC 8017). */
static EVP_PKEY *kk_rsa_pub_from_der(OSSL_LIB_CTX *libctx,
                                     const unsigned char *buf, size_t len)
{
    const unsigned char *p = buf;
    long content_len = 0;
    int tag = 0, xclass = 0;
    ASN1_INTEGER *asn1_n = NULL, *asn1_e = NULL;
    BIGNUM *n = NULL, *e = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (ASN1_get_object(&p, &content_len, &tag, &xclass, (long)len) & 0x80
            || tag != V_ASN1_SEQUENCE)
        return NULL;

    asn1_n = d2i_ASN1_INTEGER(NULL, &p, content_len);
    if (asn1_n == NULL)
        goto done;
    asn1_e = d2i_ASN1_INTEGER(NULL, &p, buf + len - p);
    if (asn1_e == NULL || p != buf + len)
        goto done;

    n = ASN1_INTEGER_to_BN(asn1_n, NULL);
    e = ASN1_INTEGER_to_BN(asn1_e, NULL);
    if (n == NULL || e == NULL)
        goto done;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n)
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)
            || (params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
        goto done;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    ASN1_INTEGER_free(asn1_n);
    ASN1_INTEGER_free(asn1_e);
    return pkey;
}

EVP_PKEY *composite_kemkey_classic_pub_from_bytes(
        OSSL_LIB_CTX *libctx, const struct composite_kem_alg_info_st *alg,
        const unsigned char *buf, size_t len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    const char *group;

    if (alg == NULL || buf == NULL || len == 0)
        return NULL;

    switch (alg->classic_type) {
    case COMP_KEM_TRAD_RSA_OAEP:
        return kk_rsa_pub_from_der(libctx, buf, len);
    case COMP_KEM_TRAD_ECDH:
        if (len != alg->trad_ct_len)
            return NULL;
        group = OBJ_nid2sn(alg->classic_param);
        if (group == NULL)
            return NULL;
        params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0);
        params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *)buf, len);
        params[2] = OSSL_PARAM_construct_end();

        pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
        if (pctx == NULL
                || EVP_PKEY_fromdata_init(pctx) <= 0
                || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY,
                                     params) <= 0) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        EVP_PKEY_CTX_free(pctx);
        return pkey;
    case COMP_KEM_TRAD_X25519:
        return len == 32
            ? EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, buf, len)
            : NULL;
    case COMP_KEM_TRAD_X448:
        return len == 56
            ? EVP_PKEY_new_raw_public_key_ex(libctx, "X448", NULL, buf, len)
            : NULL;
    }
    return NULL;
}

/* =========================================================================
 * Composite import (draft §4.1 / §4.2 wire formats)
 * ========================================================================= */

static void kk_replace_components(COMPOSITE_KEM_KEY *key,
                                  EVP_PKEY *mlkem, EVP_PKEY *classic,
                                  int is_private)
{
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);

    key->mlkem_pubkey = mlkem;
    key->classic_pubkey = classic;
    if (is_private) {
        /* The same private-capable EVP_PKEY serves both slots. */
        EVP_PKEY_up_ref(mlkem);
        EVP_PKEY_up_ref(classic);
        key->mlkem_privkey = mlkem;
        key->classic_privkey = classic;
    } else {
        key->mlkem_privkey = NULL;
        key->classic_privkey = NULL;
    }
    key->has_private = is_private;
}

int composite_kemkey_import_private(COMPOSITE_KEM_KEY *key,
                                    const unsigned char *dk, size_t dk_len)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    OSSL_LIB_CTX *libctx;
    unsigned char *seed = NULL, *trad = NULL;
    size_t seed_len = 0, trad_len = 0;
    EVP_PKEY *mlkem = NULL, *classic = NULL;
    int ret = 0;

    if (key == NULL || key->composite_name == NULL || dk == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    alg = composite_kem_alg_info_find(key->composite_name);
    if (alg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }
    libctx = key->provctx != NULL ? key->provctx->libctx : NULL;

    if (!composite_kem_privkey_decode(alg->mlkem_alg_id, dk, dk_len,
                                      &seed, &seed_len, &trad, &trad_len)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "malformed composite private key for %s",
                       alg->composite_name);
        return 0;
    }

    mlkem = kk_mlkem_priv_from_seed(libctx, alg, seed, seed_len);
    if (mlkem == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "cannot rebuild %s key from seed (requires a provider "
                       "with ML-KEM support, OpenSSL 3.5+)", alg->mlkem_name);
        goto done;
    }
    classic = kk_classic_priv_from_bytes(libctx, alg, trad, trad_len);
    if (classic == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "malformed traditional component private key for %s",
                       alg->composite_name);
        goto done;
    }

    kk_replace_components(key, mlkem, classic, 1);
    key->mlkem_name = alg->mlkem_name;
    key->classic_algorithm_name = alg->classic_name;
    mlkem = NULL;
    classic = NULL;
    ret = 1;

done:
    EVP_PKEY_free(mlkem);
    EVP_PKEY_free(classic);
    if (seed != NULL) {
        OPENSSL_cleanse(seed, seed_len);
        free(seed);            /* composite_kem_privkey_decode() uses malloc */
    }
    if (trad != NULL) {
        OPENSSL_cleanse(trad, trad_len);
        free(trad);
    }
    return ret;
}

int composite_kemkey_import_public(COMPOSITE_KEM_KEY *key,
                                   const unsigned char *ek, size_t ek_len)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    OSSL_LIB_CTX *libctx;
    unsigned char *pq = NULL, *trad = NULL;
    size_t pq_len = 0, trad_len = 0;
    EVP_PKEY *mlkem = NULL, *classic = NULL;
    int ret = 0;

    if (key == NULL || key->composite_name == NULL || ek == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    alg = composite_kem_alg_info_find(key->composite_name);
    if (alg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }
    libctx = key->provctx != NULL ? key->provctx->libctx : NULL;

    if (!composite_kem_pubkey_decode(alg->mlkem_alg_id, ek, ek_len,
                                     &pq, &pq_len, &trad, &trad_len)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "malformed composite public key for %s",
                       alg->composite_name);
        return 0;
    }

    mlkem = kk_mlkem_pub_from_raw(libctx, alg, pq, pq_len);
    if (mlkem == NULL)
        goto done;
    classic = composite_kemkey_classic_pub_from_bytes(libctx, alg,
                                                      trad, trad_len);
    if (classic == NULL)
        goto done;

    kk_replace_components(key, mlkem, classic, 0);
    key->mlkem_name = alg->mlkem_name;
    key->classic_algorithm_name = alg->classic_name;
    mlkem = NULL;
    classic = NULL;
    ret = 1;

done:
    if (!ret)
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    EVP_PKEY_free(mlkem);
    EVP_PKEY_free(classic);
    free(pq);                  /* public material — no cleanse needed */
    free(trad);
    return ret;
}

/* =========================================================================
 * Composite export (draft §4.1 / §4.2 wire formats)
 * ========================================================================= */

static int kk_classic_priv_to_bytes(const COMPOSITE_KEM_ALG_INFO *alg,
                                    EVP_PKEY *pkey,
                                    unsigned char **out, size_t *out_len)
{
    unsigned char *der = NULL;
    int der_len;
    size_t raw_len = 0;

    switch (alg->classic_type) {
    case COMP_KEM_TRAD_ECDH: {
        /*
         * Draft §10.4.2: the ECPrivateKey encoding MUST NOT carry the
         * optional publicKey field.  OpenSSL includes it by default.
         */
        int include_pub = 0;
        OSSL_PARAM ec_params[2];

        ec_params[0] = OSSL_PARAM_construct_int(
                OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, &include_pub);
        ec_params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_set_params(pkey, ec_params) <= 0)
            return 0;
    }
        /* fall through */
    case COMP_KEM_TRAD_RSA_OAEP:
        der_len = i2d_PrivateKey(pkey, &der);
        if (der_len <= 0)
            return 0;
        *out = der;
        *out_len = (size_t)der_len;
        return 1;
    case COMP_KEM_TRAD_X25519:
    case COMP_KEM_TRAD_X448:
        if (EVP_PKEY_get_raw_private_key(pkey, NULL, &raw_len) <= 0
                || !kk_alloc_octets(raw_len, out, out_len))
            return 0;
        if (EVP_PKEY_get_raw_private_key(pkey, *out, &raw_len) <= 0) {
            OPENSSL_clear_free(*out, *out_len);
            *out = NULL;
            *out_len = 0;
            return 0;
        }
        *out_len = raw_len;
        return 1;
    }
    return 0;
}

int composite_kemkey_encode_private(const COMPOSITE_KEM_KEY *key,
                                    unsigned char **out, size_t *out_len)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem, *classic;
    unsigned char seed[ML_KEM_768_PRIV_KEY_SZ]; /* 64 for both param sets */
    size_t seed_len = 0;
    unsigned char *trad = NULL;
    size_t trad_len = 0;
    unsigned char *buf = NULL;
    int ret = 0;

    if (key == NULL || out == NULL || out_len == NULL || !key->has_private)
        return 0;
    alg = composite_kem_alg_info_find(key->composite_name);
    mlkem = composite_kemkey_get0_mlkem_private(key);
    classic = composite_kemkey_get0_classic_private(key);
    if (alg == NULL || mlkem == NULL || classic == NULL)
        return 0;

    if (EVP_PKEY_get_octet_string_param(mlkem, OSSL_PKEY_PARAM_ML_KEM_SEED,
                                        seed, sizeof(seed), &seed_len) <= 0
            || seed_len != sizeof(seed)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "%s private key does not retain its seed; the draft "
                       "private key format cannot be produced", alg->mlkem_name);
        goto done;
    }

    if (!kk_classic_priv_to_bytes(alg, classic, &trad, &trad_len))
        goto done;

    buf = OPENSSL_malloc(sizeof(seed) + trad_len);
    if (buf == NULL)
        goto done;
    memcpy(buf, seed, sizeof(seed));
    memcpy(buf + sizeof(seed), trad, trad_len);

    *out = buf;
    *out_len = sizeof(seed) + trad_len;
    buf = NULL;
    ret = 1;

done:
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_clear_free(trad, trad_len);
    OPENSSL_free(buf);
    return ret;
}

int composite_kemkey_encode_public(const COMPOSITE_KEM_KEY *key,
                                   unsigned char **out, size_t *out_len)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem, *classic;
    size_t pq_len = 0, pq_expected;
    unsigned char *trad = NULL;
    size_t trad_len = 0;
    unsigned char *buf = NULL;
    int ret = 0;

    if (key == NULL || out == NULL || out_len == NULL)
        return 0;
    alg = composite_kem_alg_info_find(key->composite_name);
    mlkem = composite_kemkey_get0_mlkem_public(key);
    classic = composite_kemkey_get0_classic_public(key);
    if (alg == NULL || mlkem == NULL || classic == NULL)
        return 0;

    pq_expected = kk_mlkem_pub_size(alg->mlkem_alg_id);
    if (pq_expected == 0)
        return 0;

    if (!composite_kemkey_serialize_trad_public(alg, classic,
                                                &trad, &trad_len))
        return 0;

    buf = OPENSSL_malloc(pq_expected + trad_len);
    if (buf == NULL)
        goto done;

    if (EVP_PKEY_get_octet_string_param(mlkem, OSSL_PKEY_PARAM_PUB_KEY,
                                        buf, pq_expected, &pq_len) <= 0
            || pq_len != pq_expected)
        goto done;
    memcpy(buf + pq_expected, trad, trad_len);

    *out = buf;
    *out_len = pq_expected + trad_len;
    buf = NULL;
    ret = 1;

done:
    OPENSSL_free(trad);
    OPENSSL_free(buf);
    return ret;
}
