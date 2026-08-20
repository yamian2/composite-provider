/*
 * Encoder round-trip tests for composite KEM keys (draft §5.2 / §5.3).
 *
 * For every vector:
 *   - load dk_pkcs8, export DER/PrivateKeyInfo, and require byte identity
 *     with the vector: both sides are deterministic (version 0, parameters
 *     absent, privateKey = dk), so any structural drift shows up here;
 *   - export PEM/PrivateKeyInfo, re-import, decapsulate c, compare against k;
 *   - export the private key's public half as SPKI (DER and PEM), re-import,
 *     and require equality with a direct raw-ek import — which also checks
 *     that the public key derived from private material matches the
 *     published ek.
 */

#include "composite_test.h"

#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef COMPOSITE_KEM_HAVE_VECTORS
# include "composite_kem_test_vectors.h"
#endif

#ifndef COMPOSITE_KEM_HAVE_VECTORS

int main(void)
{
    fprintf(stderr,
            "composite KEM vectors not vendored: place testvectors.json at\n"
            "  tests/data/composite_kem_testvectors.json\n"
            "and re-run cmake.  See tests/data/README.md.\n");
    return COMPOSITE_TEST_SKIP;
}

#else

static EVP_PKEY *decode_key(const char *input_type, const char *structure,
                            int selection,
                            const unsigned char *data, size_t data_len)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, input_type, structure, NULL,
                                         selection, NULL, NULL);
    if (dctx == NULL)
        return NULL;
    if (!OSSL_DECODER_from_data(dctx, &data, &data_len)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

static unsigned char *encode_key(EVP_PKEY *pkey, int selection,
                                 const char *output_type,
                                 const char *structure, size_t *out_len)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *out = NULL;

    *out_len = 0;
    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, output_type,
                                         structure, NULL);
    if (ectx == NULL)
        return NULL;
    if (!OSSL_ENCODER_to_data(ectx, &out, out_len)) {
        OPENSSL_free(out);
        out = NULL;
        *out_len = 0;
    }
    OSSL_ENCODER_CTX_free(ectx);
    return out;
}

static int check_decaps(const char *tc_id, const char *how, EVP_PKEY *pkey,
                        const unsigned char *ct, size_t ct_len,
                        const unsigned char *expected, size_t expected_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ss[COMPOSITE_TEST_KEM_SS_LEN];
    size_t ss_len = sizeof(ss);
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
            || EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len) <= 0) {
        fprintf(stderr, "%s (%s): decapsulate failed\n", tc_id, how);
        goto done;
    }
    if (ss_len != expected_len || memcmp(ss, expected, expected_len) != 0) {
        fprintf(stderr, "%s (%s): shared secret does not match k\n",
                tc_id, how);
        goto done;
    }
    ok = 1;

done:
    OPENSSL_cleanse(ss, sizeof(ss));
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* Export pkey's public half as SPKI, re-import, compare against reference. */
static int check_spki_roundtrip(const char *tc_id, const char *output_type,
                                EVP_PKEY *pkey, EVP_PKEY *reference)
{
    unsigned char *spki = NULL;
    size_t spki_len = 0;
    EVP_PKEY *back = NULL;
    int ok = 0;

    spki = encode_key(pkey, EVP_PKEY_PUBLIC_KEY, output_type,
                      "SubjectPublicKeyInfo", &spki_len);
    if (spki == NULL) {
        fprintf(stderr, "%s: %s SubjectPublicKeyInfo export failed\n",
                tc_id, output_type);
        goto done;
    }
    back = decode_key(output_type, "SubjectPublicKeyInfo",
                      EVP_PKEY_PUBLIC_KEY, spki, spki_len);
    if (back == NULL) {
        fprintf(stderr, "%s: %s SubjectPublicKeyInfo re-import failed\n",
                tc_id, output_type);
        goto done;
    }
    if (EVP_PKEY_eq(back, reference) != 1) {
        fprintf(stderr, "%s: %s SPKI round-trip changed the key\n",
                tc_id, output_type);
        goto done;
    }
    ok = 1;

done:
    OPENSSL_free(spki);
    EVP_PKEY_free(back);
    return ok;
}

static int run_vector(const COMPOSITE_KEM_TEST_VECTOR *v)
{
    unsigned char *p8 = NULL, *ek = NULL, *ct = NULL, *expected = NULL;
    size_t p8_len = 0, ek_len = 0, ct_len = 0, expected_len = 0;
    unsigned char *der = NULL, *pem = NULL;
    size_t der_len = 0, pem_len = 0;
    EVP_PKEY *priv = NULL, *priv_der = NULL, *priv_pem = NULL, *pub = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM params[2];
    int ok = 0;

    if (v->dk_pkcs8 == NULL) {
        fprintf(stderr, "%s: vector has no dk_pkcs8\n", v->tc_id);
        goto done;
    }
    p8 = composite_test_b64(v->dk_pkcs8, &p8_len);
    ek = composite_test_b64(v->ek, &ek_len);
    ct = composite_test_b64(v->c, &ct_len);
    expected = composite_test_b64(v->k, &expected_len);
    if (p8 == NULL || ek == NULL || ct == NULL || expected == NULL) {
        fprintf(stderr, "%s: could not decode vector\n", v->tc_id);
        goto done;
    }

    priv = decode_key("DER", "PrivateKeyInfo", OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                      p8, p8_len);
    if (priv == NULL) {
        fprintf(stderr, "%s: dk_pkcs8 import failed\n", v->tc_id);
        goto done;
    }

    /* DER export must reproduce the vector byte for byte. */
    der = encode_key(priv, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo",
                     &der_len);
    if (der == NULL) {
        fprintf(stderr, "%s: DER PrivateKeyInfo export failed\n", v->tc_id);
        goto done;
    }
    if (der_len != p8_len || memcmp(der, p8, p8_len) != 0) {
        fprintf(stderr, "%s: exported DER differs from dk_pkcs8 "
                "(%zu vs %zu bytes)\n", v->tc_id, der_len, p8_len);
        goto done;
    }
    priv_der = decode_key("DER", "PrivateKeyInfo",
                          OSSL_KEYMGMT_SELECT_PRIVATE_KEY, der, der_len);
    if (priv_der == NULL
            || !check_decaps(v->tc_id, "DER round-trip", priv_der,
                             ct, ct_len, expected, expected_len))
        goto done;

    /* PEM export and re-import. */
    pem = encode_key(priv, EVP_PKEY_KEYPAIR, "PEM", "PrivateKeyInfo",
                     &pem_len);
    if (pem == NULL) {
        fprintf(stderr, "%s: PEM PrivateKeyInfo export failed\n", v->tc_id);
        goto done;
    }
    priv_pem = decode_key("PEM", NULL, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                          pem, pem_len);
    if (priv_pem == NULL
            || !check_decaps(v->tc_id, "PEM round-trip", priv_pem,
                             ct, ct_len, expected, expected_len))
        goto done;

    /* Public side: reference key straight from the vector's ek. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  ek, ek_len);
    params[1] = OSSL_PARAM_construct_end();
    pctx = EVP_PKEY_CTX_new_from_name(NULL, v->tc_id, NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pub, EVP_PKEY_PUBLIC_KEY, params) <= 0
            || pub == NULL) {
        fprintf(stderr, "%s: import from raw ek failed\n", v->tc_id);
        goto done;
    }

    /*
     * Exporting the SPKI from the private-key object checks that the public
     * half derived from private material matches the published ek.
     */
    if (!check_spki_roundtrip(v->tc_id, "DER", priv, pub)
            || !check_spki_roundtrip(v->tc_id, "PEM", pub, pub))
        goto done;

    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(priv_der);
    EVP_PKEY_free(priv_pem);
    EVP_PKEY_free(pub);
    OPENSSL_clear_free(p8, p8_len);
    OPENSSL_clear_free(der, der_len);
    OPENSSL_clear_free(pem, pem_len);
    OPENSSL_free(ek);
    OPENSSL_free(ct);
    OPENSSL_free(expected);
    return ok;
}

int main(void)
{
    COMPOSITE_TEST_PROVIDERS providers = { NULL, NULL };
    size_t i;
    int failures = 0;

    if (!composite_test_mlkem_available()) {
        fprintf(stderr, "ML-KEM unavailable in this OpenSSL build\n");
        return COMPOSITE_TEST_SKIP;
    }
    if (!composite_test_providers_load(&providers))
        return 1;

    for (i = 0; i < COMPOSITE_KEM_VECTOR_COUNT; i++) {
        if (run_vector(&composite_kem_vectors[i])) {
            printf("ok   %s\n", composite_kem_vectors[i].tc_id);
        } else {
            printf("FAIL %s\n", composite_kem_vectors[i].tc_id);
            failures++;
        }
    }

    composite_test_providers_unload(&providers);

    printf("%zu/%zu vectors passed\n",
           COMPOSITE_KEM_VECTOR_COUNT - (size_t)failures,
           COMPOSITE_KEM_VECTOR_COUNT);
    return failures == 0 ? 0 : 1;
}

#endif /* COMPOSITE_KEM_HAVE_VECTORS */
