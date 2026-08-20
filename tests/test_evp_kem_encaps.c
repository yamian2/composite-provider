#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "composite_provider.h"
#include "composite_test.h"

typedef struct {
    const char *name;
    size_t ct_len;
} KEM_ENCAPS_TEST_CASE;

static const KEM_ENCAPS_TEST_CASE test_cases[] = {
    { MLKEM768_RSA2048_SN, 1088 + 256 },
    { MLKEM768_RSA3072_SN, 1088 + 384 },
    { MLKEM768_RSA4096_SN, 1088 + 512 },
    { MLKEM768_X25519_SN, 1088 + 32 },
    { MLKEM768_P256_SN, 1088 + 65 },
    { MLKEM768_P384_SN, 1088 + 97 },
    { MLKEM768_BRAINPOOLP256_SN, 1088 + 65 },
    { MLKEM1024_RSA3072_SN, 1568 + 384 },
    { MLKEM1024_P384_SN, 1568 + 97 },
    { MLKEM1024_BRAINPOOLP384_SN, 1568 + 97 },
    { MLKEM1024_X448_SN, 1568 + 56 },
    { MLKEM1024_P521_SN, 1568 + 133 },
};

static int all_zero(const unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != 0)
            return 0;
    }
    return 1;
}

static int test_case_run(const KEM_ENCAPS_TEST_CASE *test_case)
{
    EVP_KEM *kem = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ct1 = NULL, *ct2 = NULL;
    unsigned char *ss1 = NULL, *ss2 = NULL;
    size_t ct1_len = 0, ct2_len = 0;
    size_t ss1_len = 0, ss2_len = 0;
    int ok = 0;

    kem = EVP_KEM_fetch(NULL, test_case->name, "provider=composite");
    if (kem == NULL)
        goto done;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, test_case->name,
                                      "provider=composite");
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0
            || EVP_PKEY_generate(kctx, &pkey) <= 0)
        goto done;

    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=composite");
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0)
        goto done;
    if (EVP_PKEY_encapsulate(ectx, NULL, &ct1_len, NULL, &ss1_len) <= 0)
        goto done;
    if (ct1_len != test_case->ct_len || ss1_len != 32)
        goto done;

    ct1 = OPENSSL_malloc(ct1_len);
    ss1 = OPENSSL_malloc(ss1_len);
    ct2 = OPENSSL_malloc(ct1_len);
    ss2 = OPENSSL_malloc(ss1_len);
    if (ct1 == NULL || ss1 == NULL || ct2 == NULL || ss2 == NULL)
        goto done;

    ct2_len = ct1_len;
    ss2_len = ss1_len;
    if (EVP_PKEY_encapsulate(ectx, ct1, &ct1_len, ss1, &ss1_len) <= 0)
        goto done;
    if (EVP_PKEY_encapsulate(ectx, ct2, &ct2_len, ss2, &ss2_len) <= 0)
        goto done;

    ok = ct1_len == test_case->ct_len && ct2_len == test_case->ct_len
        && ss1_len == 32 && ss2_len == 32
        && !all_zero(ct1, ct1_len)
        && !all_zero(ss1, ss1_len)
        && (ct1_len != ct2_len || memcmp(ct1, ct2, ct1_len) != 0)
        && (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0);

done:
    printf("%s encaps: %s\n", test_case->name, ok ? "PASS" : "FAIL");
    if (!ok)
        ERR_print_errors_fp(stderr);
    OPENSSL_free(ct1);
    OPENSSL_free(ct2);
    OPENSSL_clear_free(ss1, ss1_len);
    OPENSSL_clear_free(ss2, ss2_len);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(kctx);
    EVP_KEM_free(kem);
    return ok;
}

/*
 * A NULL ciphertext is the documented length query. A NULL shared secret with a
 * real ciphertext buffer is not: taking the query branch there would return
 * success having written nothing, and the caller would ship uninitialized memory
 * as its ciphertext.
 *
 * Scope note: this asserts the API contract, not the provider's own guard.
 * EVP_PKEY_encapsulate() rejects (out != NULL && secret == NULL) at
 * crypto/evp/kem.c before dispatching, so composite_kem_encapsulate() is never
 * reached on this path and this test stays green even if its guard regresses.
 * That guard is deliberate defence-in-depth for callers that drive the provider
 * dispatch table directly, and it needs a provider-level test to cover it.
 */
static int test_evp_rejects_missing_secret_buffer(void)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ct = NULL;
    size_t ct_len = 0, ss_len = 0;
    int ok = 0;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM768_P256_SN,
                                      "provider=composite");
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0
            || EVP_PKEY_generate(kctx, &pkey) <= 0)
        goto done;

    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=composite");
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0)
        goto done;
    if (EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_len) <= 0)
        goto done;

    ct = OPENSSL_malloc(ct_len);
    if (ct == NULL)
        goto done;
    memset(ct, 0xa5, ct_len);

    /* Must fail rather than silently leave ct untouched. */
    if (EVP_PKEY_encapsulate(ectx, ct, &ct_len, NULL, &ss_len) > 0)
        goto done;
    ERR_clear_error();
    ok = 1;

done:
    printf("EVP layer rejects NULL secret buffer: %s\n", ok ? "PASS" : "FAIL");
    OPENSSL_free(ct);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

/*
 * The KEM exposes no settable context parameters, so an unknown one must be
 * refused rather than accepted and dropped.
 */
static int test_unknown_param_rejected(void)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int bogus = 1;
    OSSL_PARAM params[2];
    int ok = 0;

    params[0] = OSSL_PARAM_construct_uint("composite-no-such-param", &bogus);
    params[1] = OSSL_PARAM_construct_end();

    kctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM768_P256_SN,
                                      "provider=composite");
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0
            || EVP_PKEY_generate(kctx, &pkey) <= 0)
        goto done;

    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=composite");
    if (ectx == NULL)
        goto done;
    if (EVP_PKEY_encapsulate_init(ectx, params) > 0)
        goto done;
    ERR_clear_error();
    ok = 1;

done:
    printf("encaps_init rejects unknown params: %s\n", ok ? "PASS" : "FAIL");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

int main(void)
{
    COMPOSITE_TEST_PROVIDERS providers = { NULL, NULL };
    size_t i;
    int ok = 1;

    if (!composite_test_providers_load(&providers)) {
        composite_test_providers_unload(&providers);
        return 1;
    }

    if (!composite_test_mlkem_available()) {
        printf("test_evp_kem_encaps: SKIP (no ML-KEM-768/1024 in this "
               "OpenSSL build)\n");
        composite_test_providers_unload(&providers);
        return COMPOSITE_TEST_SKIP;
    }

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        ok &= test_case_run(&test_cases[i]);

    ok &= test_evp_rejects_missing_secret_buffer();
    ok &= test_unknown_param_rejected();

    composite_test_providers_unload(&providers);
    return ok ? 0 : 1;
}
