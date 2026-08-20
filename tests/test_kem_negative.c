/*
 * Negative tests for composite KEM decapsulation and key loading.
 *
 * Each test drives a specific guard:
 *   - ciphertext one byte short / one byte long → the ctlen == mlkem+trad
 *     check in composite_kem_decapsulate()
 *   - corrupted tradCT on an RSA algorithm → RSA-OAEP decrypt failure must
 *     surface as an explicit error, never a silently wrong secret (§3.5)
 *   - undersized output buffer → PROV_R_INVALID_OUTPUT_LENGTH guard; the
 *     NULL-ss length query must succeed without touching the ciphertext
 *   - PKCS#8 with a mismatched composite OID → rejected, not coerced
 *   - PKCS#8 with non-absent AlgorithmIdentifier parameters → rejected (§5.3)
 *   - PKCS#8 truncated mid-structure → clean failure
 *   - curve confusion: a brainpoolP256r1 traditional component under
 *     id-MLKEM768-ECDH-P256-SHA3-256 imports (import is deliberately lax),
 *     but both encapsulate_init and decapsulate_init must reject it.  Both
 *     curves encode points to 65 bytes, so check_classic_key_matches() is
 *     the only guard.
 */

#include "composite_test.h"

#include <openssl/core_names.h>
#include <openssl/decoder.h>
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

static int test_count = 0;
static int test_passed = 0;

#define TEST_START(name) \
    do { test_count++; printf("Test %d: %s ... ", test_count, (name)); } while (0)
#define TEST_PASS() \
    do { test_passed++; printf("PASSED\n"); ERR_clear_error(); return 1; } while (0)
#define TEST_FAIL(msg) \
    do { printf("FAILED: %s\n", (msg)); ERR_print_errors_fp(stderr); return 0; } while (0)

static const COMPOSITE_KEM_TEST_VECTOR *find_vector(const char *tc_id)
{
    size_t i;

    for (i = 0; i < COMPOSITE_KEM_VECTOR_COUNT; i++) {
        if (strcmp(composite_kem_vectors[i].tc_id, tc_id) == 0)
            return &composite_kem_vectors[i];
    }
    return NULL;
}

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

/* Attempt a decapsulation expected to fail; 1 = it failed as required. */
static int decaps_must_fail(EVP_PKEY *pkey,
                            const unsigned char *ct, size_t ct_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ss[COMPOSITE_TEST_KEM_SS_LEN];
    size_t ss_len = sizeof(ss);
    int rc;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0; /* init itself must succeed for these tests */
    }
    rc = EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(ss, sizeof(ss));
    return rc <= 0;
}

static int try_pkcs8_decode(const unsigned char *der, size_t der_len)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int ok;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "PrivateKeyInfo", NULL,
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL);
    if (dctx == NULL)
        return 0;
    ok = OSSL_DECODER_from_data(dctx, &der, &der_len) && pkey != NULL;
    OSSL_DECODER_CTX_free(dctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/*
 * Build an unencrypted PKCS#8 blob with an arbitrary composite OID,
 * parameter type and privateKey content.  Returns the DER, or NULL.
 */
static unsigned char *build_pkcs8(const char *sn, int ptype,
                                  const unsigned char *dk, size_t dk_len,
                                  size_t *out_len)
{
    ASN1_OBJECT *aobj = NULL;
    unsigned char *dk_copy = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *der = NULL;
    int derlen = 0;
    int nid = OBJ_sn2nid(sn);

    if (nid == NID_undef)
        return NULL;
    aobj = OBJ_dup(OBJ_nid2obj(nid));
    dk_copy = OPENSSL_memdup(dk, dk_len);
    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (aobj == NULL || dk_copy == NULL || p8 == NULL
            || !PKCS8_pkey_set0(p8, aobj, 0, ptype, NULL,
                                dk_copy, (int)dk_len)) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        ASN1_OBJECT_free(aobj);
        OPENSSL_free(dk_copy);
        return NULL;
    }
    /* aobj and dk_copy now owned by p8 */

    derlen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (derlen <= 0)
        return NULL;
    *out_len = (size_t)derlen;
    return der;
}

/* -------------------------------------------------------------------------
 * Ciphertext-shape tests
 * ---------------------------------------------------------------------- */

static int test_ct_lengths(const char *tc_id)
{
    const COMPOSITE_KEM_TEST_VECTOR *v = find_vector(tc_id);
    unsigned char *dk = NULL, *ct = NULL, *long_ct = NULL;
    size_t dk_len = 0, ct_len = 0;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    TEST_START("truncated and oversized ciphertexts are rejected");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    ct = composite_test_b64(v->c, &ct_len);
    pkey = dk != NULL ? key_from_dk(v->tc_id, dk, dk_len) : NULL;
    if (pkey == NULL || ct == NULL)
        goto done;

    /* One byte short: trips the ctlen != mlkem+trad guard. */
    if (!decaps_must_fail(pkey, ct, ct_len - 1)) {
        printf("FAILED: truncated ciphertext accepted\n");
        goto out;
    }

    /* One byte long: same guard from the other side. */
    long_ct = OPENSSL_malloc(ct_len + 1);
    if (long_ct == NULL)
        goto done;
    memcpy(long_ct, ct, ct_len);
    long_ct[ct_len] = 0x00;
    if (!decaps_must_fail(pkey, long_ct, ct_len + 1)) {
        printf("FAILED: oversized ciphertext accepted\n");
        goto out;
    }

    ok = 1;

done:
    if (!ok)
        printf("FAILED: setup\n");
out:
    EVP_PKEY_free(pkey);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_free(ct);
    OPENSSL_free(long_ct);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

static int test_corrupt_rsa_tradct(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-RSA2048-SHA3-256");
    unsigned char *dk = NULL, *ct = NULL;
    size_t dk_len = 0, ct_len = 0;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    TEST_START("corrupted RSA tradCT errors explicitly");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    ct = composite_test_b64(v->c, &ct_len);
    pkey = dk != NULL ? key_from_dk(v->tc_id, dk, dk_len) : NULL;
    if (pkey == NULL || ct == NULL) {
        printf("FAILED: setup\n");
        goto out;
    }

    /*
     * The last byte lies in the RSA-OAEP half (layout is mlkemCT || tradCT).
     * OAEP's padding check makes virtually any bit flip a decrypt failure;
     * the provider must report that instead of combining garbage (§3.5).
     */
    ct[ct_len - 1] ^= 0x01;
    ok = decaps_must_fail(pkey, ct, ct_len);
    if (!ok)
        printf("FAILED: corrupted tradCT produced a shared secret\n");

out:
    EVP_PKEY_free(pkey);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_free(ct);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

static int test_output_buffer_guards(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-X25519-SHA3-256");
    unsigned char *dk = NULL, *ct = NULL;
    size_t dk_len = 0, ct_len = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char small[16];
    size_t ss_len = 0;
    int ok = 0;

    TEST_START("NULL-ss length query works; undersized ss buffer fails");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    ct = composite_test_b64(v->c, &ct_len);
    pkey = dk != NULL ? key_from_dk(v->tc_id, dk, dk_len) : NULL;
    ctx = pkey != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL) : NULL;
    if (ctx == NULL || ct == NULL
            || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        printf("FAILED: setup\n");
        goto out;
    }

    /* NULL output is the documented length query, not an error. */
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct, ct_len) <= 0
            || ss_len != COMPOSITE_TEST_KEM_SS_LEN) {
        printf("FAILED: NULL-ss length query\n");
        goto out;
    }

    /* A too-small buffer must fail up front, before any component runs. */
    ss_len = sizeof(small);
    if (EVP_PKEY_decapsulate(ctx, small, &ss_len, ct, ct_len) > 0) {
        printf("FAILED: undersized buffer accepted\n");
        goto out;
    }
    if (ss_len != COMPOSITE_TEST_KEM_SS_LEN) {
        printf("FAILED: required length not reported\n");
        goto out;
    }

    ok = 1;

out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_free(ct);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

/* -------------------------------------------------------------------------
 * PKCS#8 shape tests
 * ---------------------------------------------------------------------- */

static int test_pkcs8_wrong_oid(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-RSA2048-SHA3-256");
    unsigned char *dk = NULL, *der = NULL;
    size_t dk_len = 0, der_len = 0;
    int ok = 0;

    TEST_START("PKCS#8 with mismatched composite OID is rejected");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    if (dk == NULL) {
        printf("FAILED: setup\n");
        goto out;
    }

    /*
     * RSA2048 private material under the X25519 OID: the X25519 decoder
     * matches the OID but the dk cannot parse as seed || 32-byte scalar,
     * and no other decoder may claim it.
     */
    der = build_pkcs8(MLKEM768_X25519_SN, V_ASN1_UNDEF, dk, dk_len, &der_len);
    if (der == NULL) {
        printf("FAILED: could not build PKCS#8\n");
        goto out;
    }
    ok = !try_pkcs8_decode(der, der_len);
    if (!ok)
        printf("FAILED: mismatched OID was coerced into a key\n");

out:
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_clear_free(der, der_len);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

static int test_pkcs8_nonabsent_params(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-X25519-SHA3-256");
    unsigned char *dk = NULL, *der = NULL;
    size_t dk_len = 0, der_len = 0;
    int ok = 0;

    TEST_START("PKCS#8 with non-absent parameters is rejected");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    if (dk == NULL) {
        printf("FAILED: setup\n");
        goto out;
    }

    /* Correct OID, correct key bytes, but parameters = NULL (§5.3: MUST be
     * absent).  Only the parameter check can reject this one. */
    der = build_pkcs8(MLKEM768_X25519_SN, V_ASN1_NULL, dk, dk_len, &der_len);
    if (der == NULL) {
        printf("FAILED: could not build PKCS#8\n");
        goto out;
    }
    ok = !try_pkcs8_decode(der, der_len);
    if (!ok)
        printf("FAILED: non-absent parameters accepted\n");

out:
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_clear_free(der, der_len);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

static int test_pkcs8_truncated(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-X25519-SHA3-256");
    unsigned char *p8 = NULL;
    size_t p8_len = 0;
    int ok = 0;

    TEST_START("truncated PKCS#8 fails cleanly");

    if (v == NULL || v->dk_pkcs8 == NULL)
        TEST_FAIL("vector not found");
    p8 = composite_test_b64(v->dk_pkcs8, &p8_len);
    if (p8 == NULL || p8_len < 16) {
        printf("FAILED: setup\n");
        goto out;
    }

    /* Cut into the privateKey OCTET STRING: every d2i is bounded by the
     * buffer, so this must fail without reading past the end. */
    ok = !try_pkcs8_decode(p8, p8_len - 10);
    if (!ok)
        printf("FAILED: truncated PKCS#8 produced a key\n");

out:
    OPENSSL_clear_free(p8, p8_len);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

/* -------------------------------------------------------------------------
 * Curve confusion
 * ---------------------------------------------------------------------- */

static int test_curve_confusion(void)
{
    const COMPOSITE_KEM_TEST_VECTOR *v =
        find_vector("id-MLKEM768-ECDH-P256-SHA3-256");
    unsigned char *dk = NULL;
    size_t dk_len = 0;
    EVP_PKEY_CTX *gctx = NULL, *octx = NULL;
    EVP_PKEY *ec = NULL, *confused = NULL;
    unsigned char *ecder = NULL, *crafted = NULL;
    int ecder_len = 0;
    size_t crafted_len = 0;
    int include_pub = 0;
    OSSL_PARAM ec_params[2];
    int ok = 0;

    TEST_START("brainpoolP256r1 component under P256 OID is rejected at init");

    if (v == NULL)
        TEST_FAIL("vector not found");
    dk = composite_test_b64(v->dk, &dk_len);
    if (dk == NULL || dk_len <= 64) {
        printf("FAILED: setup\n");
        goto out;
    }

    /* A well-formed brainpoolP256r1 private key... */
    gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (gctx == NULL
            || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                    gctx, NID_brainpoolP256r1) <= 0
            || EVP_PKEY_generate(gctx, &ec) <= 0) {
        printf("FAILED: brainpool keygen\n");
        goto out;
    }
    ec_params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                            &include_pub);
    ec_params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_set_params(ec, ec_params) <= 0
            || (ecder_len = i2d_PrivateKey(ec, &ecder)) <= 0) {
        printf("FAILED: brainpool key encode\n");
        goto out;
    }

    /* ...spliced after the P256 vector's valid ML-KEM seed. */
    crafted_len = 64 + (size_t)ecder_len;
    crafted = OPENSSL_malloc(crafted_len);
    if (crafted == NULL)
        goto out;
    memcpy(crafted, dk, 64);
    memcpy(crafted + 64, ecder, (size_t)ecder_len);

    /*
     * Import is deliberately lax about the curve (the enforcement point is
     * *_init), so this must succeed — if it starts failing, the import path
     * gained a curve check and this test should move with it.
     */
    confused = key_from_dk(v->tc_id, crafted, crafted_len);
    if (confused == NULL) {
        printf("FAILED: import rejected (guard moved?)\n");
        goto out;
    }

    octx = EVP_PKEY_CTX_new_from_pkey(NULL, confused, NULL);
    if (octx == NULL) {
        printf("FAILED: ctx\n");
        goto out;
    }
    if (EVP_PKEY_decapsulate_init(octx, NULL) > 0) {
        printf("FAILED: decapsulate_init accepted the wrong curve\n");
        goto out;
    }
    ERR_clear_error();
    EVP_PKEY_CTX_free(octx);
    octx = EVP_PKEY_CTX_new_from_pkey(NULL, confused, NULL);
    if (octx == NULL) {
        printf("FAILED: ctx\n");
        goto out;
    }
    if (EVP_PKEY_encapsulate_init(octx, NULL) > 0) {
        printf("FAILED: encapsulate_init accepted the wrong curve\n");
        goto out;
    }

    ok = 1;

out:
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(octx);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(confused);
    OPENSSL_clear_free(dk, dk_len);
    OPENSSL_clear_free(crafted, crafted_len);
    if (ecder != NULL)
        OPENSSL_clear_free(ecder, (size_t)ecder_len);
    if (ok)
        TEST_PASS();
    ERR_print_errors_fp(stderr);
    return 0;
}

int main(void)
{
    COMPOSITE_TEST_PROVIDERS providers = { NULL, NULL };

    if (!composite_test_mlkem_available()) {
        fprintf(stderr, "ML-KEM unavailable in this OpenSSL build\n");
        return COMPOSITE_TEST_SKIP;
    }
    if (!composite_test_providers_load(&providers))
        return 1;

    printf("=== Composite KEM negative tests ===\n\n");

    test_ct_lengths("id-MLKEM768-RSA2048-SHA3-256");
    test_ct_lengths("id-MLKEM768-X25519-SHA3-256");
    test_corrupt_rsa_tradct();
    test_output_buffer_guards();
    test_pkcs8_wrong_oid();
    test_pkcs8_nonabsent_params();
    test_pkcs8_truncated();
    test_curve_confusion();

    composite_test_providers_unload(&providers);

    printf("\n%d/%d negative tests passed\n", test_passed, test_count);
    return test_passed == test_count ? 0 : 1;
}

#endif /* COMPOSITE_KEM_HAVE_VECTORS */
