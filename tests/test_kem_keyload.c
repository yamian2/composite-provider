/*
 * Public-key loading tests for composite KEMs (draft §4.1 / §5.2).
 *
 * For every vector:
 *   - import the raw ek and encapsulate: Encaps() is randomised (Appendix G
 *     test #1), so the assertions are success and output lengths, not values;
 *   - decapsulate the freshly produced ciphertext with the vector's dk and
 *     check both sides agree on the shared secret;
 *   - parse the x5c certificate with d2i_X509 and extract its public key.
 *     X509_get_pubkey() only succeeds if the SPKI decoder is registered and
 *     reachable, so this catches a decoder that exists but is never
 *     dispatched;
 *   - check the certificate's key equals the raw-ek import.
 */

#include "composite_test.h"

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/x509.h>
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

static EVP_PKEY *key_from_raw(const char *alg_name, const char *param_name,
                              int selection,
                              const unsigned char *raw, size_t raw_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(param_name,
                                                  (void *)raw, raw_len);
    params[1] = OSSL_PARAM_construct_end();

    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pkey, selection, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Encapsulate with pub, decapsulate with priv, and require both sides to
 * agree.  expected_ct_len comes from the vector's c.
 */
static int check_encaps_roundtrip(const char *tc_id, const char *how,
                                  EVP_PKEY *pub, EVP_PKEY *priv,
                                  size_t expected_ct_len)
{
    EVP_PKEY_CTX *ectx = NULL, *dctx = NULL;
    unsigned char *ct = NULL, *ss = NULL, *ss2 = NULL;
    size_t ct_len = 0, ss_len = 0, ss2_len = 0;
    int ok = 0;

    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        fprintf(stderr, "%s (%s): encapsulate_init failed\n", tc_id, how);
        goto done;
    }
    if (EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_len) <= 0) {
        fprintf(stderr, "%s (%s): encapsulate length query failed\n",
                tc_id, how);
        goto done;
    }
    if (ct_len != expected_ct_len || ss_len != COMPOSITE_TEST_KEM_SS_LEN) {
        fprintf(stderr, "%s (%s): lengths ct=%zu (want %zu) ss=%zu (want %d)\n",
                tc_id, how, ct_len, expected_ct_len, ss_len,
                COMPOSITE_TEST_KEM_SS_LEN);
        goto done;
    }
    ct = OPENSSL_malloc(ct_len);
    ss = OPENSSL_malloc(ss_len);
    if (ct == NULL || ss == NULL)
        goto done;
    if (EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss, &ss_len) <= 0) {
        fprintf(stderr, "%s (%s): encapsulate failed\n", tc_id, how);
        goto done;
    }

    dctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        fprintf(stderr, "%s (%s): decapsulate_init failed\n", tc_id, how);
        goto done;
    }
    ss2_len = ss_len;
    ss2 = OPENSSL_malloc(ss2_len);
    if (ss2 == NULL)
        goto done;
    if (EVP_PKEY_decapsulate(dctx, ss2, &ss2_len, ct, ct_len) <= 0) {
        fprintf(stderr, "%s (%s): decapsulate of fresh ct failed\n",
                tc_id, how);
        goto done;
    }
    if (ss2_len != ss_len || memcmp(ss, ss2, ss_len) != 0) {
        fprintf(stderr, "%s (%s): encaps/decaps secrets disagree\n",
                tc_id, how);
        goto done;
    }

    ok = 1;

done:
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    OPENSSL_free(ct);
    OPENSSL_clear_free(ss, ss_len);
    OPENSSL_clear_free(ss2, ss2_len);
    return ok;
}

static int run_vector(const COMPOSITE_KEM_TEST_VECTOR *v)
{
    unsigned char *ek = NULL, *dk = NULL, *c = NULL, *x5c = NULL;
    size_t ek_len = 0, dk_len = 0, c_len = 0, x5c_len = 0;
    EVP_PKEY *pub = NULL, *priv = NULL, *cert_pub = NULL;
    X509 *cert = NULL;
    int ok = 0;

    ek = composite_test_b64(v->ek, &ek_len);
    dk = composite_test_b64(v->dk, &dk_len);
    c = composite_test_b64(v->c, &c_len);
    if (ek == NULL || dk == NULL || c == NULL) {
        fprintf(stderr, "%s: could not decode vector\n", v->tc_id);
        goto done;
    }

    pub = key_from_raw(v->tc_id, OSSL_PKEY_PARAM_PUB_KEY,
                       EVP_PKEY_PUBLIC_KEY, ek, ek_len);
    if (pub == NULL) {
        fprintf(stderr, "%s: import from raw ek failed\n", v->tc_id);
        goto done;
    }
    priv = key_from_raw(v->tc_id, OSSL_PKEY_PARAM_PRIV_KEY,
                        EVP_PKEY_KEYPAIR, dk, dk_len);
    if (priv == NULL) {
        fprintf(stderr, "%s: import from raw dk failed\n", v->tc_id);
        goto done;
    }

    if (!check_encaps_roundtrip(v->tc_id, "raw ek", pub, priv, c_len))
        goto done;

    /* The certificate path: SPKI decoder registration under test. */
    if (v->x5c == NULL) {
        fprintf(stderr, "%s: vector has no x5c\n", v->tc_id);
        goto done;
    }
    x5c = composite_test_b64(v->x5c, &x5c_len);
    if (x5c != NULL) {
        const unsigned char *p = x5c;

        cert = d2i_X509(NULL, &p, (long)x5c_len);
    }
    if (cert == NULL) {
        fprintf(stderr, "%s: d2i_X509 failed\n", v->tc_id);
        goto done;
    }
    cert_pub = X509_get_pubkey(cert);
    if (cert_pub == NULL) {
        fprintf(stderr, "%s: X509_get_pubkey failed (SPKI decoder not "
                "reached?)\n", v->tc_id);
        goto done;
    }
    if (!EVP_PKEY_is_a(cert_pub, v->tc_id)) {
        fprintf(stderr, "%s: certificate key has the wrong type\n", v->tc_id);
        goto done;
    }
    if (EVP_PKEY_eq(cert_pub, pub) != 1) {
        fprintf(stderr, "%s: certificate key differs from raw ek import\n",
                v->tc_id);
        goto done;
    }
    if (!check_encaps_roundtrip(v->tc_id, "x5c", cert_pub, priv, c_len))
        goto done;

    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(cert_pub);
    X509_free(cert);
    OPENSSL_free(ek);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_free(c);
    OPENSSL_free(x5c);
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
