#include "composite_kem.h"
#include "composite_kem_encoding.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdlib.h>   /* free() -- composite_kem_ct_decode uses malloc() */
#include <string.h>

static OSSL_FUNC_kem_freectx_fn composite_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn composite_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn composite_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn composite_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn composite_kem_decapsulate;
static OSSL_FUNC_kem_get_ctx_params_fn composite_kem_get_ctx_params;
static OSSL_FUNC_kem_gettable_ctx_params_fn composite_kem_gettable_ctx_params;
static OSSL_FUNC_kem_set_ctx_params_fn composite_kem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn composite_kem_settable_ctx_params;

void *composite_kem_newctx_base(void *provctx, const char *alg_sn)
{
    COMPOSITE_KEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->provctx = (COMPOSITE_CTX *)provctx;
    ctx->algorithm_name = alg_sn;
    ctx->alg_info = composite_kem_alg_info_find(alg_sn);
    return ctx;
}

static void composite_kem_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

/*
 * This provider exposes no settable KEM context parameters, so anything the
 * caller passes would otherwise be dropped while we reported success.
 */
static int composite_kem_reject_params(const OSSL_PARAM params[])
{
    if (params != NULL && params[0].key != NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "composite KEM takes no context parameters, got \"%s\"",
                       params[0].key);
        return 0;
    }
    return 1;
}

/*
 * Confirm the traditional component really is the algorithm the composite OID
 * names. The serialized-length checks further down cannot separate curves of
 * equal size - P-256 and brainpoolP256r1 are both 65 bytes, P-384 and
 * brainpoolP384r1 both 97 - and the combiner label binds one specific curve, so
 * accepting the wrong one would be exactly the algorithm substitution the label
 * exists to prevent.
 */
static int check_classic_key_matches(const COMPOSITE_KEM_ALG_INFO *alg,
                                     EVP_PKEY *pkey)
{
    char group[80];
    int nid;

    switch (alg->classic_type) {
    case COMP_KEM_TRAD_RSA_OAEP:
        if (EVP_PKEY_is_a(pkey, DEFAULT_RSA_NAME)
                && EVP_PKEY_get_bits(pkey) == alg->classic_param)
            return 1;
        break;
    case COMP_KEM_TRAD_ECDH:
        if (!EVP_PKEY_is_a(pkey, "EC")
                || !EVP_PKEY_get_utf8_string_param(pkey,
                                                   OSSL_PKEY_PARAM_GROUP_NAME,
                                                   group, sizeof(group), NULL))
            break;
        nid = OBJ_txt2nid(group);
        if (nid == NID_undef)
            nid = EC_curve_nist2nid(group);
        if (nid == alg->classic_param)
            return 1;
        break;
    case COMP_KEM_TRAD_X25519:
        if (EVP_PKEY_is_a(pkey, "X25519"))
            return 1;
        break;
    case COMP_KEM_TRAD_X448:
        if (EVP_PKEY_is_a(pkey, "X448"))
            return 1;
        break;
    }

    ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                   "traditional component key does not match %s",
                   alg->composite_name);
    return 0;
}

static int composite_kem_encapsulate_init(void *ctx, void *provkey,
                                          const OSSL_PARAM params[])
{
    COMPOSITE_KEM_CTX *kem_ctx = (COMPOSITE_KEM_CTX *)ctx;
    COMPOSITE_KEM_KEY *key = (COMPOSITE_KEM_KEY *)provkey;
    const char *alg_name;

    if (kem_ctx == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!composite_kem_reject_params(params))
        return 0;

    alg_name = kem_ctx->algorithm_name != NULL
        ? kem_ctx->algorithm_name
        : key->composite_name;
    kem_ctx->alg_info = composite_kem_alg_info_find(alg_name);
    if (kem_ctx->alg_info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }
    if (key->composite_name != NULL
            && strcmp(key->composite_name,
                      kem_ctx->alg_info->composite_name) != 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (composite_kemkey_get0_mlkem_public(key) == NULL
            || composite_kemkey_get0_classic_public(key) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (!EVP_PKEY_is_a(composite_kemkey_get0_mlkem_public(key),
                       kem_ctx->alg_info->mlkem_name)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "ML-KEM component key is not %s",
                       kem_ctx->alg_info->mlkem_name);
        return 0;
    }
    if (!check_classic_key_matches(kem_ctx->alg_info,
                                   composite_kemkey_get0_classic_public(key)))
        return 0;

    kem_ctx->key = key; /* Borrowed provider-side key, matching signature ctx. */
    return 1;
}

static int generate_component_key(OSSL_LIB_CTX *libctx, const char *algorithm,
                                  int parameter, EVP_PKEY **pkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (pkey == NULL)
        return 0;
    *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, algorithm, NULL);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0)
        goto done;

    if (strcmp(algorithm, "EC") == 0) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, parameter) <= 0)
            goto done;
    }

    ret = EVP_PKEY_generate(pctx, pkey) > 0;
done:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int alloc_octets(size_t len, unsigned char **out, size_t *out_len)
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

static int serialize_raw_public(EVP_PKEY *pkey, size_t expected_len,
                                unsigned char **out, size_t *out_len)
{
    size_t len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) <= 0)
        return 0;
    if (len != expected_len)
        return 0;
    if (!alloc_octets(len, out, out_len))
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

static int serialize_encoded_public(EVP_PKEY *pkey, size_t expected_len,
                                    unsigned char **out, size_t *out_len)
{
    size_t len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        NULL, 0, &len) <= 0)
        return 0;
    if (expected_len != 0 && len != expected_len)
        return 0;
    if (!alloc_octets(len, out, out_len))
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

static int serialize_rsa_public(EVP_PKEY *pkey, unsigned char **out,
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

static int serialize_trad_public_key(const COMPOSITE_KEM_ALG_INFO *alg,
                                     EVP_PKEY *pkey,
                                     unsigned char **out, size_t *out_len)
{
    switch (alg->classic_type) {
    case COMP_KEM_TRAD_RSA_OAEP:
        return serialize_rsa_public(pkey, out, out_len);
    case COMP_KEM_TRAD_ECDH:
        return serialize_encoded_public(pkey, alg->trad_ct_len, out, out_len);
    case COMP_KEM_TRAD_X25519:
        return serialize_raw_public(pkey, 32, out, out_len);
    case COMP_KEM_TRAD_X448:
        return serialize_raw_public(pkey, 56, out, out_len);
    }
    return 0;
}

static int component_mlkem_encapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                       const COMPOSITE_KEM_ALG_INFO *alg,
                                       unsigned char **ct, size_t *ct_len,
                                       unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (pctx == NULL || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0)
        goto done;

    if (EVP_PKEY_encapsulate(pctx, NULL, ct_len, NULL, ss_len) <= 0)
        goto done;
    if (*ct_len != alg->mlkem_ct_len || *ss_len != alg->mlkem_ss_len)
        goto done;
    if (!alloc_octets(*ct_len, ct, ct_len)
            || !alloc_octets(*ss_len, ss, ss_len))
        goto done;
    if (EVP_PKEY_encapsulate(pctx, *ct, ct_len, *ss, ss_len) <= 0)
        goto done;
    ret = *ct_len == alg->mlkem_ct_len && *ss_len == alg->mlkem_ss_len;

done:
    if (!ret) {
        OPENSSL_free(*ct);
        OPENSSL_clear_free(*ss, *ss_len);
        *ct = NULL;
        *ss = NULL;
        *ct_len = 0;
        *ss_len = 0;
    }
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int component_rsa_oaep_encapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                          const COMPOSITE_KEM_ALG_INFO *alg,
                                          unsigned char **ct, size_t *ct_len,
                                          unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD *sha256 = NULL;
    int ret = 0;

    if (!alloc_octets(ML_KEM_SS_SZ, ss, ss_len))
        goto done;
    if (RAND_bytes_ex(libctx, *ss, *ss_len, 0) <= 0)
        goto done;

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    sha256 = EVP_MD_fetch(libctx, "SHA-256", NULL);
    if (pctx == NULL || sha256 == NULL)
        goto done;
    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, sha256) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, sha256) <= 0)
        goto done;
    if (EVP_PKEY_encrypt(pctx, NULL, ct_len, *ss, *ss_len) <= 0)
        goto done;
    if (*ct_len != alg->trad_ct_len)
        goto done;
    if (!alloc_octets(*ct_len, ct, ct_len))
        goto done;
    if (EVP_PKEY_encrypt(pctx, *ct, ct_len, *ss, *ss_len) <= 0)
        goto done;
    ret = *ct_len == alg->trad_ct_len;

done:
    if (!ret) {
        OPENSSL_free(*ct);
        OPENSSL_clear_free(*ss, *ss_len);
        *ct = NULL;
        *ss = NULL;
        *ct_len = 0;
        *ss_len = 0;
    }
    EVP_MD_free(sha256);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int component_dh_encapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *peer,
                                    const COMPOSITE_KEM_ALG_INFO *alg,
                                    unsigned char **ct, size_t *ct_len,
                                    unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY *eph = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    int ret = 0;

    if (!generate_component_key(libctx, alg->classic_name, alg->classic_param,
                                &eph))
        goto done;

    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, eph, NULL);
    if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0)
        goto done;
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0)
        goto done;
    if (EVP_PKEY_derive(dctx, NULL, ss_len) <= 0)
        goto done;
    if (!alloc_octets(*ss_len, ss, ss_len))
        goto done;
    if (EVP_PKEY_derive(dctx, *ss, ss_len) <= 0)
        goto done;
    if (!serialize_trad_public_key(alg, eph, ct, ct_len))
        goto done;
    ret = *ct_len == alg->trad_ct_len;

done:
    if (!ret) {
        OPENSSL_free(*ct);
        OPENSSL_clear_free(*ss, *ss_len);
        *ct = NULL;
        *ss = NULL;
        *ct_len = 0;
        *ss_len = 0;
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(eph);
    return ret;
}

static int component_trad_encapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                      const COMPOSITE_KEM_ALG_INFO *alg,
                                      unsigned char **ct, size_t *ct_len,
                                      unsigned char **ss, size_t *ss_len)
{
    if (alg->classic_type == COMP_KEM_TRAD_RSA_OAEP)
        return component_rsa_oaep_encapsulate(libctx, pkey, alg, ct, ct_len,
                                              ss, ss_len);
    return component_dh_encapsulate(libctx, pkey, alg, ct, ct_len, ss, ss_len);
}

static int composite_kem_encapsulate(void *ctx, unsigned char *ct, size_t *ctlen,
                                     unsigned char *ss, size_t *sslen)
{
    COMPOSITE_KEM_CTX *kem_ctx = (COMPOSITE_KEM_CTX *)ctx;
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem_key;
    EVP_PKEY *trad_key;
    OSSL_LIB_CTX *libctx;
    size_t required_ct_len;
    size_t required_ss_len;
    unsigned char *mlkem_ct = NULL, *mlkem_ss = NULL;
    unsigned char *trad_ct = NULL, *trad_ss = NULL, *trad_pk = NULL;
    size_t mlkem_ct_len = 0, mlkem_ss_len = 0;
    size_t trad_ct_len = 0, trad_ss_len = 0, trad_pk_len = 0;
    size_t out_len;
    int ret = 0;

    if (kem_ctx == NULL || ctlen == NULL || sslen == NULL
            || kem_ctx->key == NULL || kem_ctx->alg_info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    alg = kem_ctx->alg_info;
    required_ct_len = alg->mlkem_ct_len + alg->trad_ct_len;
    required_ss_len = alg->final_ss_len;

    if (ct == NULL) {
        *ctlen = required_ct_len;
        *sslen = required_ss_len;
        return 1;
    }
    /*
     * A NULL ciphertext is the documented length query. A NULL shared secret
     * with a non-NULL ciphertext is not: reporting success there would leave the
     * caller's ciphertext buffer untouched and it would transmit uninitialized
     * memory believing encapsulation had run.
     */
    if (ss == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
                       "composite KEM cannot produce a ciphertext without a "
                       "shared secret buffer; pass a NULL ciphertext to query "
                       "the required lengths");
        return 0;
    }
    if (*ctlen < required_ct_len || *sslen < required_ss_len) {
        *ctlen = required_ct_len;
        *sslen = required_ss_len;
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
        return 0;
    }

    libctx = kem_ctx->provctx->libctx;
    mlkem_key = composite_kemkey_get0_mlkem_public(kem_ctx->key);
    trad_key = composite_kemkey_get0_classic_public(kem_ctx->key);
    if (mlkem_key == NULL || trad_key == NULL)
        return 0;

    if (!component_mlkem_encapsulate(libctx, mlkem_key, alg, &mlkem_ct,
                                     &mlkem_ct_len, &mlkem_ss, &mlkem_ss_len))
        goto done;
    if (!component_trad_encapsulate(libctx, trad_key, alg, &trad_ct,
                                    &trad_ct_len, &trad_ss, &trad_ss_len))
        goto done;
    if (!serialize_trad_public_key(alg, trad_key, &trad_pk, &trad_pk_len))
        goto done;

    out_len = *ctlen;
    if (!composite_kem_ct_encode(alg->mlkem_alg_id, mlkem_ct, mlkem_ct_len,
                                 trad_ct, trad_ct_len, ct, &out_len))
        goto done;
    if (out_len != required_ct_len)
        goto done;

    out_len = *sslen;
    if (!composite_kem_combine_shared_secret(libctx, alg, mlkem_ss,
                                             mlkem_ss_len, trad_ss,
                                             trad_ss_len, trad_ct,
                                             trad_ct_len, trad_pk, trad_pk_len,
                                             ss, &out_len))
        goto done;

    *ctlen = required_ct_len;
    *sslen = out_len;
    ret = 1;

done:
    OPENSSL_free(mlkem_ct);
    OPENSSL_clear_free(mlkem_ss, mlkem_ss_len);
    OPENSSL_free(trad_ct);
    OPENSSL_clear_free(trad_ss, trad_ss_len);
    OPENSSL_free(trad_pk);
    return ret;
}

static int composite_kem_decapsulate_init(void *ctx, void *provkey,
                                          const OSSL_PARAM params[])
{
    COMPOSITE_KEM_CTX *kem_ctx = (COMPOSITE_KEM_CTX *)ctx;
    COMPOSITE_KEM_KEY *key = (COMPOSITE_KEM_KEY *)provkey;
    const char *alg_name;

    if (kem_ctx == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!composite_kem_reject_params(params))
        return 0;

    alg_name = kem_ctx->algorithm_name != NULL
        ? kem_ctx->algorithm_name
        : key->composite_name;
    kem_ctx->alg_info = composite_kem_alg_info_find(alg_name);
    if (kem_ctx->alg_info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }
    if (key->composite_name != NULL
            && strcmp(key->composite_name,
                      kem_ctx->alg_info->composite_name) != 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /*
     * Decapsulation needs the private half of both components. Checking
     * has_private rather than the get0_*_private() accessors matters: those
     * fall back to the public key when no private one is set, so a public-only
     * key would pass a NULL check and then fail deep inside EVP_PKEY_derive()
     * or EVP_PKEY_decrypt() with an error that says nothing about the cause.
     */
    if (!key->has_private) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "%s key has no private component; decapsulation "
                       "requires one", kem_ctx->alg_info->composite_name);
        return 0;
    }
    if (composite_kemkey_get0_mlkem_private(key) == NULL
            || composite_kemkey_get0_classic_private(key) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (!EVP_PKEY_is_a(composite_kemkey_get0_mlkem_private(key),
                       kem_ctx->alg_info->mlkem_name)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "ML-KEM component key is not %s",
                       kem_ctx->alg_info->mlkem_name);
        return 0;
    }
    if (!check_classic_key_matches(kem_ctx->alg_info,
                                   composite_kemkey_get0_classic_private(key)))
        return 0;

    kem_ctx->key = key; /* Borrowed provider-side key, as in encapsulate_init. */
    return 1;
}

static int component_mlkem_decapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                       const COMPOSITE_KEM_ALG_INFO *alg,
                                       const unsigned char *ct, size_t ct_len,
                                       unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    /*
     * Draft 3.3: a ciphertext component of the wrong length is malformed input
     * and must be rejected, not handed to the primitive.
     */
    if (ct_len != alg->mlkem_ct_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "ML-KEM ciphertext is %zu bytes, expected %zu",
                       ct_len, alg->mlkem_ct_len);
        return 0;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (pctx == NULL || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0)
        goto done;

    if (EVP_PKEY_decapsulate(pctx, NULL, ss_len, ct, ct_len) <= 0)
        goto done;
    if (*ss_len != alg->mlkem_ss_len)
        goto done;
    if (!alloc_octets(*ss_len, ss, ss_len))
        goto done;
    if (EVP_PKEY_decapsulate(pctx, *ss, ss_len, ct, ct_len) <= 0)
        goto done;
    ret = *ss_len == alg->mlkem_ss_len;

done:
    if (!ret) {
        OPENSSL_clear_free(*ss, *ss_len);
        *ss = NULL;
        *ss_len = 0;
    }
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
 * ML-KEM's implicit rejection means a corrupted ML-KEM ciphertext yields a
 * pseudorandom secret rather than an error, so there is nothing to check here
 * beyond the length: the mismatch surfaces as a wrong combined secret.
 */
static int component_dh_decapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *own,
                                    const COMPOSITE_KEM_ALG_INFO *alg,
                                    const unsigned char *ct, size_t ct_len,
                                    unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    int ret = 0;

    if (ct_len != alg->trad_ct_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "traditional ciphertext is %zu bytes, expected %zu",
                       ct_len, alg->trad_ct_len);
        return 0;
    }

    /*
     * tradCT is the sender's ephemeral public key. Rebuilding it through
     * composite_kemkey_classic_pub_from_bytes() rather than a bare
     * EVP_PKEY_new_raw_public_key() keeps the group named by the composite OID
     * bound to the point: an EC point of the right length on the wrong curve is
     * rejected here rather than silently deriving on the attacker's curve.
     */
    peer = composite_kemkey_classic_pub_from_bytes(libctx, alg, ct, ct_len);
    if (peer == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "malformed traditional ciphertext for %s",
                       alg->composite_name);
        goto done;
    }

    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, own, NULL);
    if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0)
        goto done;
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0)
        goto done;
    if (EVP_PKEY_derive(dctx, NULL, ss_len) <= 0)
        goto done;
    if (!alloc_octets(*ss_len, ss, ss_len))
        goto done;
    if (EVP_PKEY_derive(dctx, *ss, ss_len) <= 0)
        goto done;
    ret = 1;

done:
    if (!ret) {
        OPENSSL_clear_free(*ss, *ss_len);
        *ss = NULL;
        *ss_len = 0;
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    return ret;
}

static int component_rsa_oaep_decapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                          const COMPOSITE_KEM_ALG_INFO *alg,
                                          const unsigned char *ct, size_t ct_len,
                                          unsigned char **ss, size_t *ss_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD *sha256 = NULL;
    size_t out_len = 0;
    int ret = 0;

    /*
     * Length is checked before decrypting, per draft 3.3: passing a
     * wrong-length buffer to RSA-OAEP would either fail inside the padding
     * check or, worse, succeed against a differently sized modulus.
     */
    if (ct_len != alg->trad_ct_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "RSA ciphertext is %zu bytes, expected %zu",
                       ct_len, alg->trad_ct_len);
        return 0;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    sha256 = EVP_MD_fetch(libctx, "SHA-256", NULL);
    if (pctx == NULL || sha256 == NULL)
        goto done;
    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, sha256) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, sha256) <= 0)
        goto done;
    /* Empty label, matching encapsulation: no set_rsa_oaep_label call. */

    if (EVP_PKEY_decrypt(pctx, NULL, &out_len, ct, ct_len) <= 0)
        goto done;
    if (!alloc_octets(out_len, ss, ss_len))
        goto done;
    if (EVP_PKEY_decrypt(pctx, *ss, ss_len, ct, ct_len) <= 0)
        goto done;

    /*
     * Draft 3.3: tradSS is a fixed 32 octets. A decrypt that succeeds but
     * returns a different length means the ciphertext was not produced by this
     * scheme; feeding it to the combiner would produce a plausible-looking
     * secret from malformed input.
     */
    if (*ss_len != ML_KEM_SS_SZ) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "RSA-OAEP recovered %zu bytes, expected %d",
                       *ss_len, ML_KEM_SS_SZ);
        goto done;
    }
    ret = 1;

done:
    if (!ret) {
        OPENSSL_clear_free(*ss, *ss_len);
        *ss = NULL;
        *ss_len = 0;
    }
    EVP_MD_free(sha256);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int component_trad_decapsulate(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                                      const COMPOSITE_KEM_ALG_INFO *alg,
                                      const unsigned char *ct, size_t ct_len,
                                      unsigned char **ss, size_t *ss_len)
{
    if (alg->classic_type == COMP_KEM_TRAD_RSA_OAEP)
        return component_rsa_oaep_decapsulate(libctx, pkey, alg, ct, ct_len,
                                              ss, ss_len);
    return component_dh_decapsulate(libctx, pkey, alg, ct, ct_len, ss, ss_len);
}

static int composite_kem_decapsulate(void *ctx, unsigned char *ss, size_t *sslen,
                                     const unsigned char *ct, size_t ctlen)
{
    COMPOSITE_KEM_CTX *kem_ctx = (COMPOSITE_KEM_CTX *)ctx;
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem_key;
    EVP_PKEY *trad_key;
    OSSL_LIB_CTX *libctx;
    size_t required_ct_len;
    unsigned char *mlkem_ct = NULL, *trad_ct = NULL;
    unsigned char *mlkem_ss = NULL, *trad_ss = NULL, *trad_pk = NULL;
    size_t mlkem_ct_len = 0, trad_ct_len = 0;
    size_t mlkem_ss_len = 0, trad_ss_len = 0, trad_pk_len = 0;
    size_t out_len;
    int ret = 0;

    if (kem_ctx == NULL || sslen == NULL || kem_ctx->key == NULL
            || kem_ctx->alg_info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    alg = kem_ctx->alg_info;
    required_ct_len = alg->mlkem_ct_len + alg->trad_ct_len;

    /* A NULL shared-secret buffer is the documented length query. */
    if (ss == NULL) {
        *sslen = alg->final_ss_len;
        return 1;
    }
    if (ct == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (*sslen < alg->final_ss_len) {
        *sslen = alg->final_ss_len;
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
        return 0;
    }
    /*
     * Total length is validated before splitting. composite_kem_ct_decode()
     * takes the ML-KEM half on its fixed size and treats the remainder as the
     * traditional half, so without this a ciphertext of any length >= the
     * ML-KEM component would parse and only fail later, on a component whose
     * error says nothing about the real problem.
     */
    if (ctlen != required_ct_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "composite ciphertext is %zu bytes, expected %zu",
                       ctlen, required_ct_len);
        return 0;
    }

    libctx = kem_ctx->provctx->libctx;
    mlkem_key = composite_kemkey_get0_mlkem_private(kem_ctx->key);
    trad_key = composite_kemkey_get0_classic_private(kem_ctx->key);
    if (mlkem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!composite_kem_ct_decode(alg->mlkem_alg_id, ct, ctlen,
                                 &mlkem_ct, &mlkem_ct_len,
                                 &trad_ct, &trad_ct_len))
        goto done;

    /*
     * Both components must succeed before the combiner runs. Draft 3.3
     * requires malformed input to be reported as an error rather than absorbed
     * into a shared secret, so there is no fallback path here -- a failed
     * component aborts.
     */
    if (!component_mlkem_decapsulate(libctx, mlkem_key, alg, mlkem_ct,
                                     mlkem_ct_len, &mlkem_ss, &mlkem_ss_len))
        goto done;
    if (!component_trad_decapsulate(libctx, trad_key, alg, trad_ct,
                                    trad_ct_len, &trad_ss, &trad_ss_len))
        goto done;

    /*
     * Draft 10.4 option 1: recover tradPK from the private key rather than
     * trusting a copy carried alongside the ciphertext. The combiner binds the
     * recipient's public key into the KDF input, so taking it from anywhere the
     * sender controls would let the sender choose part of that input.
     */
    if (!serialize_trad_public_key(alg, trad_key, &trad_pk, &trad_pk_len))
        goto done;

    out_len = *sslen;
    if (!composite_kem_combine_shared_secret(libctx, alg, mlkem_ss,
                                             mlkem_ss_len, trad_ss,
                                             trad_ss_len, trad_ct,
                                             trad_ct_len, trad_pk, trad_pk_len,
                                             ss, &out_len))
        goto done;

    *sslen = out_len;
    ret = 1;

done:
    /*
     * composite_kem_ct_decode() allocates with malloc(), not OPENSSL_malloc(),
     * so its buffers are released with free(). The component secrets come from
     * alloc_octets() and are OPENSSL_clear_free'd. Mixing the two would be a
     * heap error on builds where OpenSSL uses a custom allocator.
     */
    OPENSSL_clear_free(mlkem_ss, mlkem_ss_len);
    OPENSSL_clear_free(trad_ss, trad_ss_len);
    OPENSSL_free(trad_pk);
    free(mlkem_ct);
    free(trad_ct);
    return ret;
}

static int composite_kem_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int composite_kem_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    return composite_kem_reject_params(params);
}

static const OSSL_PARAM *composite_kem_settable_ctx_params(ossl_unused void *vctx,
    ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = { OSSL_PARAM_END };

    return known_settable_ctx_params;
}

static const OSSL_PARAM *composite_kem_gettable_ctx_params(ossl_unused void *vctx,
    ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = { OSSL_PARAM_END };

    return known_gettable_ctx_params;
}

KEM_DISPATCH_TABLE(mlkem768_rsa2048, MLKEM768_RSA2048_SN)
KEM_DISPATCH_TABLE(mlkem768_rsa3072, MLKEM768_RSA3072_SN)
KEM_DISPATCH_TABLE(mlkem768_rsa4096, MLKEM768_RSA4096_SN)
KEM_DISPATCH_TABLE(mlkem768_x25519, MLKEM768_X25519_SN)
KEM_DISPATCH_TABLE(mlkem768_p256, MLKEM768_P256_SN)
KEM_DISPATCH_TABLE(mlkem768_p384, MLKEM768_P384_SN)
KEM_DISPATCH_TABLE(mlkem768_brainpoolp256, MLKEM768_BRAINPOOLP256_SN)
KEM_DISPATCH_TABLE(mlkem1024_rsa3072, MLKEM1024_RSA3072_SN)
KEM_DISPATCH_TABLE(mlkem1024_p384, MLKEM1024_P384_SN)
KEM_DISPATCH_TABLE(mlkem1024_brainpoolp384, MLKEM1024_BRAINPOOLP384_SN)
KEM_DISPATCH_TABLE(mlkem1024_x448, MLKEM1024_X448_SN)
KEM_DISPATCH_TABLE(mlkem1024_p521, MLKEM1024_P521_SN)
