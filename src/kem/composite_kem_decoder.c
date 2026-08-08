/*
 * composite_kem_decoder.c — DER decoder for composite KEM key types
 *
 * Implements OSSL_OP_DECODER for:
 *   - PrivateKeyInfo / DER        (unencrypted PKCS#8, draft §5.3)
 *   - SubjectPublicKeyInfo / DER  (public keys, incl. X.509 certificates, §5.2)
 *
 * Wire formats inside the ASN.1 wrapping are the draft's raw concatenations:
 *   privateKey OCTET STRING content:  dk = mlkemSeed(64) || tradSK   (§4.2)
 *   subjectPublicKey BIT STRING:      ek = mlkemPK || tradPK         (§4.1)
 *
 * Differences from the signature-side decoder this is modelled on:
 *   - AlgorithmIdentifier.parameters MUST be absent (§5.2/§5.3) and is
 *     checked; the signature decoder does not enforce this.
 *   - PrivateKeyInfo is parsed manually rather than via
 *     d2i(PKCS8_PRIV_KEY_INFO): OpenSSL's template rejects the optional
 *     OneAsymmetricKey publicKey [1] field outright, whereas the draft allows
 *     it.  The manual parse ignores anything after the privateKey OCTET
 *     STRING — the public key is always re-derived from the private material,
 *     never trusted from the encoding, so a mismatched [1] cannot change the
 *     combiner input.
 */

#include "composite_kem_decoder.h"
#include "composite_kem_key.h"
#include "composite_kem_info.h"
#include "provider_ctx.h"
#include "composite_provider.h"

#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

/* =========================================================================
 * Decoder context
 * ========================================================================= */

typedef struct {
    COMPOSITE_CTX *provctx;
    const char    *composite_name; /* static SN string, e.g. MLKEM768_X25519_SN */
} COMPOSITE_KEM_DEC_CTX;

static void kem_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/*
 * Read all DER bytes from the core BIO.
 *
 * As with the signature decoder, ASN1_item_d2i_bio(X509_PUBKEY, ...) must be
 * avoided on the SPKI path: its d2i callback re-enters the OSSL_DECODER
 * framework with the same data and recurses back into this decoder (see
 * composite_decoder.c).  Reading raw bytes and parsing with plain d2i
 * primitives sidesteps that for both structures.
 */
static unsigned char *kem_dec_read_der(COMPOSITE_KEM_DEC_CTX *ctx,
                                       OSSL_CORE_BIO *cin, long *out_len)
{
    BIO *in = BIO_new_from_core_bio(ctx->provctx->libctx, cin);
    unsigned char *derbuf = NULL;
    long derlen = 0;
    unsigned char chunk[4096];
    int n;

    if (in == NULL)
        return NULL;

    while ((n = BIO_read(in, chunk, (int)sizeof(chunk))) > 0) {
        unsigned char *tmp = OPENSSL_realloc(derbuf, (size_t)(derlen + n));

        if (tmp == NULL) {
            OPENSSL_clear_free(derbuf, (size_t)derlen);
            derbuf = NULL;
            derlen = 0;
            break;
        }
        derbuf = tmp;
        memcpy(derbuf + derlen, chunk, (size_t)n);
        derlen += (long)n;
    }
    OPENSSL_cleanse(chunk, sizeof(chunk));
    BIO_free(in);

    if (derlen == 0) {
        OPENSSL_free(derbuf);
        return NULL;
    }
    *out_len = derlen;
    return derbuf;
}

/*
 * Check that an AlgorithmIdentifier names this decoder's composite algorithm
 * and carries no parameters.  §5.2 and §5.3 both say parameters MUST be
 * absent; accepting a NULL (or anything else) would let two different
 * encodings of the same key coexist.
 */
static int kem_dec_check_algor(const COMPOSITE_KEM_DEC_CTX *ctx,
                               const X509_ALGOR *alg)
{
    const ASN1_OBJECT *aobj = NULL;
    const void *pval = NULL;
    int ptype = 0;
    int nid_expected = OBJ_sn2nid(ctx->composite_name);

    X509_ALGOR_get0(&aobj, &ptype, &pval, alg);
    if (OBJ_obj2nid(aobj) == NID_undef
            || OBJ_obj2nid(aobj) != nid_expected)
        return 0;
    if (ptype != V_ASN1_UNDEF) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "%s: AlgorithmIdentifier parameters MUST be absent",
                       ctx->composite_name);
        return 0;
    }
    return 1;
}

/* Hand a decoded key to the framework via a KEYMGMT_LOAD reference. */
static int kem_dec_object_cb(COMPOSITE_KEM_DEC_CTX *ctx,
                             COMPOSITE_KEM_KEY **key,
                             OSSL_CALLBACK *object_cb, void *object_cbarg)
{
    int obj_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[4];
    int ret;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type);
    params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, key, sizeof(*key));
    params[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)ctx->composite_name, 0);
    params[3] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);
    if (ret)
        *key = NULL; /* ownership transferred via KEYMGMT_LOAD */
    return ret;
}

/* =========================================================================
 * PrivateKeyInfo / DER decoder
 * ========================================================================= */

static int kem_pki_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int kem_pki_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_KEM_DEC_CTX *ctx    = (COMPOSITE_KEM_DEC_CTX *)vctx;
    unsigned char         *derbuf = NULL;
    long                   derlen = 0;
    const unsigned char   *p, *content_end;
    long                   seqlen = 0;
    int                    tag, xclass;
    ASN1_INTEGER          *version = NULL;
    X509_ALGOR            *alg     = NULL;
    ASN1_OCTET_STRING     *pkey    = NULL;
    COMPOSITE_KEM_KEY     *key     = NULL;
    long                   vers;
    /*
     * "Could not decode" is not an error to the framework: returning 0 from
     * a decode function is fatal and aborts the entire decoder chain, so a
     * mismatched OID in one decoder would break dispatch for every other
     * algorithm.  Data that is not ours returns 1 with no object callback.
     */
    int                    ret     = 1;

    (void)pw_cb; (void)pw_cbarg;

    if (selection != 0 && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1; /* not our selection — not an error, let others try */

    derbuf = kem_dec_read_der(ctx, cin, &derlen);
    if (derbuf == NULL)
        return 0;

    /*
     * OneAsymmetricKey ::= SEQUENCE {
     *     version                  INTEGER,      -- 0, or 1 with publicKey
     *     privateKeyAlgorithm      AlgorithmIdentifier,
     *     privateKey               OCTET STRING, -- dk, §4.2
     *     attributes           [0] IMPLICIT Attributes OPTIONAL,
     *     publicKey            [1] IMPLICIT BIT STRING OPTIONAL }
     */
    p = derbuf;
    if (ASN1_get_object(&p, &seqlen, &tag, &xclass, derlen) & 0x80
            || tag != V_ASN1_SEQUENCE)
        goto done;
    content_end = p + seqlen;

    version = d2i_ASN1_INTEGER(NULL, &p, content_end - p);
    if (version == NULL)
        goto done;
    vers = ASN1_INTEGER_get(version);
    if (vers != 0 && vers != 1)
        goto done;

    alg = d2i_X509_ALGOR(NULL, &p, content_end - p);
    if (alg == NULL || !kem_dec_check_algor(ctx, alg))
        goto done;

    pkey = d2i_ASN1_OCTET_STRING(NULL, &p, content_end - p);
    if (pkey == NULL || ASN1_STRING_get0_data(pkey) == NULL
            || ASN1_STRING_length(pkey) <= 0)
        goto done;
    /* attributes [0] / publicKey [1] between p and content_end: ignored. */

    key = composite_kemkey_new();
    if (key == NULL) {
        ret = 0;
        goto done;
    }
    key->provctx = ctx->provctx;
    key->composite_name = ctx->composite_name;

    /*
     * Rebuilds both components and derives the public halves from the private
     * material.  A publicKey [1] field, if present, is never consulted: a
     * lying encoding must not be able to change what the combiner hashes.
     */
    if (!composite_kemkey_import_private(key, ASN1_STRING_get0_data(pkey),
                                         (size_t)ASN1_STRING_length(pkey)))
        goto done;

    ret = kem_dec_object_cb(ctx, &key, object_cb, object_cbarg);

done:
    ASN1_INTEGER_free(version);
    X509_ALGOR_free(alg);
    if (pkey != NULL && pkey->data != NULL)
        OPENSSL_cleanse(pkey->data, (size_t)pkey->length);
    ASN1_OCTET_STRING_free(pkey);
    OPENSSL_clear_free(derbuf, (size_t)derlen);
    composite_kemkey_free(key);
    return ret;
}

/* =========================================================================
 * SubjectPublicKeyInfo / DER decoder
 * ========================================================================= */

static int kem_spki_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int kem_spki_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                           OSSL_CALLBACK *object_cb, void *object_cbarg,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_KEM_DEC_CTX *ctx    = (COMPOSITE_KEM_DEC_CTX *)vctx;
    unsigned char         *derbuf = NULL;
    long                   derlen = 0;
    const unsigned char   *p;
    long                   seqlen = 0;
    int                    tag, xclass;
    X509_ALGOR            *alg    = NULL;
    ASN1_BIT_STRING       *bs     = NULL;
    COMPOSITE_KEM_KEY     *key    = NULL;
    int                    ret    = 1; /* see kem_pki_decode: 0 is fatal */

    (void)pw_cb; (void)pw_cbarg;

    if (selection != 0 && !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1;

    derbuf = kem_dec_read_der(ctx, cin, &derlen);
    if (derbuf == NULL)
        return 0;

    p = derbuf;
    if (ASN1_get_object(&p, &seqlen, &tag, &xclass, derlen) & 0x80
            || tag != V_ASN1_SEQUENCE)
        goto done;

    alg = d2i_X509_ALGOR(NULL, &p, seqlen);
    if (alg == NULL || !kem_dec_check_algor(ctx, alg))
        goto done;

    bs = d2i_ASN1_BIT_STRING(NULL, &p, derbuf + derlen - p);
    if (bs == NULL || ASN1_STRING_get0_data(bs) == NULL
            || ASN1_STRING_length(bs) <= 0)
        goto done;
    /*
     * ek is a whole number of octets, so the BIT STRING's unused-bits count
     * must be zero.  d2i records it in the low three flag bits.
     */
    if ((bs->flags & ASN1_STRING_FLAG_BITS_LEFT) != 0
            && (bs->flags & 0x07) != 0)
        goto done;

    key = composite_kemkey_new();
    if (key == NULL) {
        ret = 0;
        goto done;
    }
    key->provctx = ctx->provctx;
    key->composite_name = ctx->composite_name;

    if (!composite_kemkey_import_public(key, ASN1_STRING_get0_data(bs),
                                        (size_t)ASN1_STRING_length(bs)))
        goto done;

    ret = kem_dec_object_cb(ctx, &key, object_cb, object_cbarg);

done:
    X509_ALGOR_free(alg);
    ASN1_BIT_STRING_free(bs);
    OPENSSL_free(derbuf);
    composite_kemkey_free(key);
    return ret;
}

/* =========================================================================
 * Per-algorithm dispatch tables
 *
 * Each composite algorithm needs its own newctx so the decoder context
 * carries the correct composite_name (SN).  The decode logic is shared.
 * ========================================================================= */

#define MAKE_KEM_DECODERS(id, SN)                                              \
static void *kem_##id##_dec_newctx(void *provctx)                              \
{                                                                              \
    COMPOSITE_KEM_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                 \
    if (ctx != NULL) {                                                         \
        ctx->provctx        = (COMPOSITE_CTX *)provctx;                        \
        ctx->composite_name = (SN);                                            \
    }                                                                          \
    return ctx;                                                                \
}                                                                              \
static const OSSL_DISPATCH kem_##id##_pki_dec_funcs[] = {                      \
    { OSSL_FUNC_DECODER_NEWCTX,         (void(*)(void))kem_##id##_dec_newctx }, \
    { OSSL_FUNC_DECODER_FREECTX,        (void(*)(void))kem_dec_freectx },       \
    { OSSL_FUNC_DECODER_DOES_SELECTION, (void(*)(void))kem_pki_does_selection },\
    { OSSL_FUNC_DECODER_DECODE,         (void(*)(void))kem_pki_decode },        \
    OSSL_DISPATCH_END                                                          \
};                                                                             \
static const OSSL_DISPATCH kem_##id##_spki_dec_funcs[] = {                     \
    { OSSL_FUNC_DECODER_NEWCTX,         (void(*)(void))kem_##id##_dec_newctx }, \
    { OSSL_FUNC_DECODER_FREECTX,        (void(*)(void))kem_dec_freectx },       \
    { OSSL_FUNC_DECODER_DOES_SELECTION, (void(*)(void))kem_spki_does_selection },\
    { OSSL_FUNC_DECODER_DECODE,         (void(*)(void))kem_spki_decode },       \
    OSSL_DISPATCH_END                                                          \
}

MAKE_KEM_DECODERS(mlkem768_rsa2048,       MLKEM768_RSA2048_SN);
MAKE_KEM_DECODERS(mlkem768_rsa3072,       MLKEM768_RSA3072_SN);
MAKE_KEM_DECODERS(mlkem768_rsa4096,       MLKEM768_RSA4096_SN);
MAKE_KEM_DECODERS(mlkem768_x25519,        MLKEM768_X25519_SN);
MAKE_KEM_DECODERS(mlkem768_p256,          MLKEM768_P256_SN);
MAKE_KEM_DECODERS(mlkem768_p384,          MLKEM768_P384_SN);
MAKE_KEM_DECODERS(mlkem768_brainpoolp256, MLKEM768_BRAINPOOLP256_SN);
MAKE_KEM_DECODERS(mlkem1024_rsa3072,      MLKEM1024_RSA3072_SN);
MAKE_KEM_DECODERS(mlkem1024_p384,         MLKEM1024_P384_SN);
MAKE_KEM_DECODERS(mlkem1024_brainpoolp384, MLKEM1024_BRAINPOOLP384_SN);
MAKE_KEM_DECODERS(mlkem1024_x448,         MLKEM1024_X448_SN);
MAKE_KEM_DECODERS(mlkem1024_p521,         MLKEM1024_P521_SN);

/* =========================================================================
 * OSSL_ALGORITHM table
 * ========================================================================= */

#define KEM_NAMES(ln, sn, oid) ln ":" sn ":" oid

#define KEM_PKI_DEC(names, id)                                                 \
    { names,                                                                   \
      "provider=composite,input=der,structure=PrivateKeyInfo",                 \
      kem_##id##_pki_dec_funcs, NULL }

#define KEM_SPKI_DEC(names, id)                                                \
    { names,                                                                   \
      "provider=composite,input=der,structure=SubjectPublicKeyInfo",           \
      kem_##id##_spki_dec_funcs, NULL }

#define KEM_DECS(ln, sn, oid, id)                                              \
    KEM_PKI_DEC(KEM_NAMES(ln, sn, oid), id),                                   \
    KEM_SPKI_DEC(KEM_NAMES(ln, sn, oid), id)

const OSSL_ALGORITHM *composite_kem_decoders(void *provctx)
{
    static const OSSL_ALGORITHM algorithms[] = {
        KEM_DECS(MLKEM768_RSA2048_LN, MLKEM768_RSA2048_SN,
                 MLKEM768_RSA2048_OID, mlkem768_rsa2048),
        KEM_DECS(MLKEM768_RSA3072_LN, MLKEM768_RSA3072_SN,
                 MLKEM768_RSA3072_OID, mlkem768_rsa3072),
        KEM_DECS(MLKEM768_RSA4096_LN, MLKEM768_RSA4096_SN,
                 MLKEM768_RSA4096_OID, mlkem768_rsa4096),
        KEM_DECS(MLKEM768_X25519_LN, MLKEM768_X25519_SN,
                 MLKEM768_X25519_OID, mlkem768_x25519),
        KEM_DECS(MLKEM768_P256_LN, MLKEM768_P256_SN,
                 MLKEM768_P256_OID, mlkem768_p256),
        KEM_DECS(MLKEM768_P384_LN, MLKEM768_P384_SN,
                 MLKEM768_P384_OID, mlkem768_p384),
        KEM_DECS(MLKEM768_BRAINPOOLP256_LN, MLKEM768_BRAINPOOLP256_SN,
                 MLKEM768_BRAINPOOLP256_OID, mlkem768_brainpoolp256),
        KEM_DECS(MLKEM1024_RSA3072_LN, MLKEM1024_RSA3072_SN,
                 MLKEM1024_RSA3072_OID, mlkem1024_rsa3072),
        KEM_DECS(MLKEM1024_P384_LN, MLKEM1024_P384_SN,
                 MLKEM1024_P384_OID, mlkem1024_p384),
        KEM_DECS(MLKEM1024_BRAINPOOLP384_LN, MLKEM1024_BRAINPOOLP384_SN,
                 MLKEM1024_BRAINPOOLP384_OID, mlkem1024_brainpoolp384),
        KEM_DECS(MLKEM1024_X448_LN, MLKEM1024_X448_SN,
                 MLKEM1024_X448_OID, mlkem1024_x448),
        KEM_DECS(MLKEM1024_P521_LN, MLKEM1024_P521_SN,
                 MLKEM1024_P521_OID, mlkem1024_p521),
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    return algorithms;
}
