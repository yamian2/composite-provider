/*
 * composite_kem_encoder.c — PEM/DER encoder for composite KEM key types
 *
 * Implements OSSL_OP_ENCODER for:
 *   - PrivateKeyInfo / PEM and DER   (unencrypted PKCS#8, draft §5.3)
 *   - SubjectPublicKeyInfo / PEM and DER (§5.2)
 *
 * The DER/PrivateKeyInfo variant is one the signature-side encoder does not
 * have: it is what i2d_PKCS8PrivateKeyInfo and OSSL_ENCODER with output=der
 * request, and without it those calls fail as a silent "unsupported".
 *
 * All twelve composite KEMs share the same four dispatch tables; the
 * per-algorithm OID is resolved at encode-time via OBJ_sn2nid() on the key's
 * composite_name field.  AlgorithmIdentifier parameters are left absent
 * (V_ASN1_UNDEF), as §5.2/§5.3 require.
 */

#include "composite_kem_encoder.h"
#include "composite_kem_key.h"
#include "provider_ctx.h"
#include "composite_provider.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* =========================================================================
 * Encoder context
 * ========================================================================= */

typedef struct {
    COMPOSITE_CTX *provctx;
} COMPOSITE_KEM_ENC_CTX;

static void *kem_enc_newctx(void *provctx)
{
    COMPOSITE_KEM_ENC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = (COMPOSITE_CTX *)provctx;
    return ctx;
}

static void kem_enc_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/* Cross-provider key passing not supported: encode only our own key objects. */
static void *kem_enc_import_object(void *vctx, int selection,
                                   const OSSL_PARAM params[])
{
    (void)vctx; (void)selection; (void)params;
    return NULL;
}

static void kem_enc_free_object(void *key)
{
    composite_kemkey_free((COMPOSITE_KEM_KEY *)key);
}

/* =========================================================================
 * Shared helpers
 * ========================================================================= */

static ASN1_OBJECT *kem_alg_obj_for_key(const COMPOSITE_KEM_KEY *key)
{
    int nid = OBJ_sn2nid(key->composite_name);

    if (nid == NID_undef) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return NULL;
    }
    return OBJ_dup(OBJ_nid2obj(nid));
}

/*
 * Build the PrivateKeyInfo for a composite KEM key: version 0, the composite
 * OID with absent parameters, and dk (§4.2) as the privateKey content.
 * PKCS8_pkey_set0 takes ownership of the OID and the dk buffer on success.
 */
static PKCS8_PRIV_KEY_INFO *kem_build_p8info(const COMPOSITE_KEM_KEY *key)
{
    ASN1_OBJECT *aobj = NULL;
    unsigned char *dk = NULL;
    size_t dk_len = 0;
    PKCS8_PRIV_KEY_INFO *p8info = NULL;

    aobj = kem_alg_obj_for_key(key);
    if (aobj == NULL)
        return NULL;

    if (!composite_kemkey_encode_private(key, &dk, &dk_len)) {
        ASN1_OBJECT_free(aobj);
        return NULL;
    }

    p8info = PKCS8_PRIV_KEY_INFO_new();
    if (p8info == NULL
            || !PKCS8_pkey_set0(p8info, aobj, 0, V_ASN1_UNDEF, NULL,
                                dk, (int)dk_len)) {
        PKCS8_PRIV_KEY_INFO_free(p8info);
        ASN1_OBJECT_free(aobj);
        OPENSSL_clear_free(dk, dk_len);
        return NULL;
    }
    return p8info;
}

/*
 * Free a PrivateKeyInfo, cleansing the seed and traditional private material
 * it owns first — PKCS8_PRIV_KEY_INFO_free alone would only free it.
 */
static void kem_free_p8info(PKCS8_PRIV_KEY_INFO *p8info)
{
    const ASN1_OBJECT *aobj = NULL;
    const unsigned char *pk = NULL;
    int pklen = 0;

    if (p8info == NULL)
        return;
    if (PKCS8_pkey_get0(&aobj, &pk, &pklen, NULL, p8info) && pk != NULL)
        OPENSSL_cleanse((void *)pk, (size_t)pklen);
    PKCS8_PRIV_KEY_INFO_free(p8info);
}

/*
 * Build the X509_PUBKEY (SubjectPublicKeyInfo) for a composite KEM key with
 * ek (§4.1) as the subjectPublicKey BIT STRING.  set0_param takes ownership
 * of the OID and the ek buffer on success.
 */
static X509_PUBKEY *kem_build_xpk(const COMPOSITE_KEM_KEY *key)
{
    ASN1_OBJECT *aobj = NULL;
    unsigned char *ek = NULL;
    size_t ek_len = 0;
    X509_PUBKEY *xpk = NULL;

    aobj = kem_alg_obj_for_key(key);
    if (aobj == NULL)
        return NULL;

    if (!composite_kemkey_encode_public(key, &ek, &ek_len)) {
        ASN1_OBJECT_free(aobj);
        return NULL;
    }

    xpk = X509_PUBKEY_new();
    if (xpk == NULL
            || !X509_PUBKEY_set0_param(xpk, aobj, V_ASN1_UNDEF, NULL,
                                       ek, (int)ek_len)) {
        X509_PUBKEY_free(xpk);
        ASN1_OBJECT_free(aobj);
        OPENSSL_free(ek);
        return NULL;
    }
    return xpk;
}

/* =========================================================================
 * PrivateKeyInfo encoders (PEM and DER)
 * ========================================================================= */

static int kem_pki_does_selection(void *vctx, int selection)
{
    (void)vctx;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int kem_pki_encode(COMPOSITE_KEM_ENC_CTX *ctx, OSSL_CORE_BIO *cout,
                          const void *key_in, const OSSL_PARAM key_abstract[],
                          int selection, int as_pem)
{
    const COMPOSITE_KEM_KEY *key = (const COMPOSITE_KEM_KEY *)key_in;
    PKCS8_PRIV_KEY_INFO *p8info = NULL;
    BIO *out = NULL;
    int ret = 0;

    /* Only accept a directly-passed key object, not abstract params. */
    if (key_abstract != NULL || key == NULL)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 0;

    p8info = kem_build_p8info(key);
    if (p8info == NULL)
        return 0;

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out != NULL) {
        ret = as_pem
            ? PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info)
            : i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);
        BIO_free(out);
    }
    kem_free_p8info(p8info);
    return ret;
}

static int kem_pki_pem_encode(void *vctx, OSSL_CORE_BIO *cout,
                              const void *key_in,
                              const OSSL_PARAM key_abstract[], int selection,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    (void)cb; (void)cbarg;
    return kem_pki_encode((COMPOSITE_KEM_ENC_CTX *)vctx, cout, key_in,
                          key_abstract, selection, 1);
}

static int kem_pki_der_encode(void *vctx, OSSL_CORE_BIO *cout,
                              const void *key_in,
                              const OSSL_PARAM key_abstract[], int selection,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    (void)cb; (void)cbarg;
    return kem_pki_encode((COMPOSITE_KEM_ENC_CTX *)vctx, cout, key_in,
                          key_abstract, selection, 0);
}

/* =========================================================================
 * SubjectPublicKeyInfo encoders (PEM and DER)
 * ========================================================================= */

static int kem_spki_does_selection(void *vctx, int selection)
{
    (void)vctx;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int kem_spki_encode(COMPOSITE_KEM_ENC_CTX *ctx, OSSL_CORE_BIO *cout,
                           const void *key_in, const OSSL_PARAM key_abstract[],
                           int selection, int as_pem)
{
    const COMPOSITE_KEM_KEY *key = (const COMPOSITE_KEM_KEY *)key_in;
    X509_PUBKEY *xpk = NULL;
    BIO *out = NULL;
    int ret = 0;

    if (key_abstract != NULL || key == NULL)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 0;

    xpk = kem_build_xpk(key);
    if (xpk == NULL)
        return 0;

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out != NULL) {
        if (as_pem) {
            ret = PEM_write_bio_X509_PUBKEY(out, xpk);
        } else {
            unsigned char *der = NULL;
            int derlen = i2d_X509_PUBKEY(xpk, &der);

            if (derlen > 0)
                ret = BIO_write(out, der, derlen) == derlen;
            OPENSSL_free(der);
        }
        BIO_free(out);
    }
    X509_PUBKEY_free(xpk);
    return ret;
}

static int kem_spki_pem_encode(void *vctx, OSSL_CORE_BIO *cout,
                               const void *key_in,
                               const OSSL_PARAM key_abstract[], int selection,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    (void)cb; (void)cbarg;
    return kem_spki_encode((COMPOSITE_KEM_ENC_CTX *)vctx, cout, key_in,
                           key_abstract, selection, 1);
}

static int kem_spki_der_encode(void *vctx, OSSL_CORE_BIO *cout,
                               const void *key_in,
                               const OSSL_PARAM key_abstract[], int selection,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    (void)cb; (void)cbarg;
    return kem_spki_encode((COMPOSITE_KEM_ENC_CTX *)vctx, cout, key_in,
                           key_abstract, selection, 0);
}

/* =========================================================================
 * Dispatch tables (shared by all 12 algorithms)
 * ========================================================================= */

#define KEM_ENCODER_FUNCS(name, does_selection, encode)                        \
static const OSSL_DISPATCH name[] = {                                          \
    { OSSL_FUNC_ENCODER_NEWCTX,         (void(*)(void))kem_enc_newctx },       \
    { OSSL_FUNC_ENCODER_FREECTX,        (void(*)(void))kem_enc_freectx },      \
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))does_selection },       \
    { OSSL_FUNC_ENCODER_ENCODE,         (void(*)(void))encode },               \
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (void(*)(void))kem_enc_import_object },\
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (void(*)(void))kem_enc_free_object },  \
    OSSL_DISPATCH_END                                                          \
}

KEM_ENCODER_FUNCS(kem_pki_pem_encoder_functions,
                  kem_pki_does_selection, kem_pki_pem_encode);
KEM_ENCODER_FUNCS(kem_pki_der_encoder_functions,
                  kem_pki_does_selection, kem_pki_der_encode);
KEM_ENCODER_FUNCS(kem_spki_pem_encoder_functions,
                  kem_spki_does_selection, kem_spki_pem_encode);
KEM_ENCODER_FUNCS(kem_spki_der_encoder_functions,
                  kem_spki_does_selection, kem_spki_der_encode);

/* =========================================================================
 * OSSL_ALGORITHM table
 * ========================================================================= */

#define KEM_NAMES(ln, sn, oid) ln ":" sn ":" oid

/*
 * The output= / structure= property strings are what OSSL_ENCODER selects
 * on; a typo here fails with nothing useful on the error queue, so they are
 * written once and stamped for all four variants.
 */
#define KEM_ENCS(ln, sn, oid)                                                  \
    { KEM_NAMES(ln, sn, oid),                                                  \
      "provider=composite,output=pem,structure=PrivateKeyInfo",                \
      kem_pki_pem_encoder_functions, NULL },                                   \
    { KEM_NAMES(ln, sn, oid),                                                  \
      "provider=composite,output=der,structure=PrivateKeyInfo",                \
      kem_pki_der_encoder_functions, NULL },                                   \
    { KEM_NAMES(ln, sn, oid),                                                  \
      "provider=composite,output=pem,structure=SubjectPublicKeyInfo",          \
      kem_spki_pem_encoder_functions, NULL },                                  \
    { KEM_NAMES(ln, sn, oid),                                                  \
      "provider=composite,output=der,structure=SubjectPublicKeyInfo",          \
      kem_spki_der_encoder_functions, NULL }

const OSSL_ALGORITHM *composite_kem_encoders(void *provctx)
{
    static const OSSL_ALGORITHM algorithms[] = {
        KEM_ENCS(MLKEM768_RSA2048_LN, MLKEM768_RSA2048_SN,
                 MLKEM768_RSA2048_OID),
        KEM_ENCS(MLKEM768_RSA3072_LN, MLKEM768_RSA3072_SN,
                 MLKEM768_RSA3072_OID),
        KEM_ENCS(MLKEM768_RSA4096_LN, MLKEM768_RSA4096_SN,
                 MLKEM768_RSA4096_OID),
        KEM_ENCS(MLKEM768_X25519_LN, MLKEM768_X25519_SN,
                 MLKEM768_X25519_OID),
        KEM_ENCS(MLKEM768_P256_LN, MLKEM768_P256_SN,
                 MLKEM768_P256_OID),
        KEM_ENCS(MLKEM768_P384_LN, MLKEM768_P384_SN,
                 MLKEM768_P384_OID),
        KEM_ENCS(MLKEM768_BRAINPOOLP256_LN, MLKEM768_BRAINPOOLP256_SN,
                 MLKEM768_BRAINPOOLP256_OID),
        KEM_ENCS(MLKEM1024_RSA3072_LN, MLKEM1024_RSA3072_SN,
                 MLKEM1024_RSA3072_OID),
        KEM_ENCS(MLKEM1024_P384_LN, MLKEM1024_P384_SN,
                 MLKEM1024_P384_OID),
        KEM_ENCS(MLKEM1024_BRAINPOOLP384_LN, MLKEM1024_BRAINPOOLP384_SN,
                 MLKEM1024_BRAINPOOLP384_OID),
        KEM_ENCS(MLKEM1024_X448_LN, MLKEM1024_X448_SN,
                 MLKEM1024_X448_OID),
        KEM_ENCS(MLKEM1024_P521_LN, MLKEM1024_P521_SN,
                 MLKEM1024_P521_OID),
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    return algorithms;
}
