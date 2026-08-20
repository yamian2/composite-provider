/*
 * Known-answer tests for composite KEM decapsulation.
 *
 * Every vector is driven through the public EVP interface rather than the
 * provider functions directly, so a decapsulation that works internally but is
 * not reachable through OpenSSL's dispatch still fails here.
 *
 * The generated header is optional at build time: without
 * tests/data/composite_kem_testvectors.json there is nothing to test against,
 * and this reports as a skip rather than a pass.
 */

#include "composite_test.h"

#include <openssl/core_names.h>
#include <openssl/decoder.h>
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

/*
 * Build a composite KEM key from the raw dk of draft 4.2.
 *
 * EVP_PKEY_fromdata() with OSSL_PKEY_PARAM_PRIV_KEY is the same path an
 * application would take, which means this also exercises the keymgmt import
 * dispatch rather than reaching into the provider's key structure.
 */
static EVP_PKEY *key_from_dk(const char *alg_name,
                             const unsigned char *dk, size_t dk_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  (void *)dk, dk_len);
    params[1] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Build a composite KEM key from the vector's dk_pkcs8 through the public
 * OSSL_DECODER API with no key type hint.  Leaving the type NULL forces
 * OpenSSL to dispatch on the PKCS#8 AlgorithmIdentifier OID across every
 * registered decoder, so this fails if the decoder exists but its
 * registration wiring (provider query, keymgmt LOAD, OID) is broken.
 */
static EVP_PKEY *key_from_pkcs8(const unsigned char *der, size_t der_len)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "PrivateKeyInfo",
                                         NULL, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        return NULL;
    if (!OSSL_DECODER_from_data(dctx, &der, &der_len)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

/* Decapsulate ct with pkey and compare against the vector's k. */
static int check_decaps(const char *tc_id, const char *how, EVP_PKEY *pkey,
                        const unsigned char *ct, size_t ct_len,
                        const unsigned char *expected, size_t expected_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ss = NULL;
    size_t ss_len = 0;
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        fprintf(stderr, "%s (%s): decapsulate_init failed\n", tc_id, how);
        goto done;
    }

    /* Length query first, then the real call, as an application would. */
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct, ct_len) <= 0) {
        fprintf(stderr, "%s (%s): decapsulate length query failed\n",
                tc_id, how);
        goto done;
    }
    if (ss_len != expected_len) {
        fprintf(stderr, "%s (%s): reported secret length %zu, vector k is %zu\n",
                tc_id, how, ss_len, expected_len);
        goto done;
    }
    ss = OPENSSL_malloc(ss_len);
    if (ss == NULL)
        goto done;
    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len) <= 0) {
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
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_clear_free(ss, ss_len);
    return ok;
}

static int run_vector(const COMPOSITE_KEM_TEST_VECTOR *v)
{
    unsigned char *dk = NULL, *p8 = NULL, *ct = NULL, *expected = NULL;
    size_t dk_len = 0, p8_len = 0, ct_len = 0, expected_len = 0;
    EVP_PKEY *pkey = NULL, *pkey_p8 = NULL;
    int ok = 0;

    dk = composite_test_b64(v->dk, &dk_len);
    ct = composite_test_b64(v->c, &ct_len);
    expected = composite_test_b64(v->k, &expected_len);
    if (dk == NULL || ct == NULL || expected == NULL) {
        fprintf(stderr, "%s: could not decode vector\n", v->tc_id);
        goto done;
    }

    pkey = key_from_dk(v->tc_id, dk, dk_len);
    if (pkey == NULL) {
        fprintf(stderr, "%s: import from raw dk failed\n", v->tc_id);
        goto done;
    }
    if (!check_decaps(v->tc_id, "raw dk", pkey, ct, ct_len,
                      expected, expected_len))
        goto done;

    /* Same vector again, loaded from PKCS#8 — both must yield the same k. */
    if (v->dk_pkcs8 == NULL) {
        fprintf(stderr, "%s: vector has no dk_pkcs8\n", v->tc_id);
        goto done;
    }
    p8 = composite_test_b64(v->dk_pkcs8, &p8_len);
    if (p8 == NULL) {
        fprintf(stderr, "%s: could not decode dk_pkcs8\n", v->tc_id);
        goto done;
    }
    pkey_p8 = key_from_pkcs8(p8, p8_len);
    if (pkey_p8 == NULL) {
        fprintf(stderr, "%s: OSSL_DECODER load from dk_pkcs8 failed\n",
                v->tc_id);
        goto done;
    }
    if (!EVP_PKEY_is_a(pkey_p8, v->tc_id)) {
        fprintf(stderr, "%s: dk_pkcs8 decoded to the wrong key type\n",
                v->tc_id);
        goto done;
    }
    if (!check_decaps(v->tc_id, "dk_pkcs8", pkey_p8, ct, ct_len,
                      expected, expected_len))
        goto done;

    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey_p8);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_clear_free(p8, p8_len);
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
