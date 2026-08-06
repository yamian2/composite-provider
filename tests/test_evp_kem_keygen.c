#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

#include "composite_provider.h"
#include "composite_test.h"

typedef struct {
    const char *name;
    int security_bits;
} KEM_TEST_CASE;

static const KEM_TEST_CASE test_cases[] = {
    { MLKEM768_RSA2048_SN, 112 },
    { MLKEM768_RSA3072_SN, 128 },
    { MLKEM768_RSA4096_SN, 152 },
    { MLKEM768_X25519_SN, 128 },
    { MLKEM768_P256_SN, 128 },
    { MLKEM768_P384_SN, 192 },
    { MLKEM768_BRAINPOOLP256_SN, 128 },
    { MLKEM1024_RSA3072_SN, 128 },
    { MLKEM1024_P384_SN, 192 },
    { MLKEM1024_BRAINPOOLP384_SN, 192 },
    { MLKEM1024_X448_SN, 224 },
    { MLKEM1024_P521_SN, 256 },
};

static int test_algorithm(const KEM_TEST_CASE *test_case)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, test_case->name, "provider=composite");
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_generate(ctx, &pkey) <= 0)
        goto done;

    ok = pkey != NULL
        && EVP_PKEY_is_a(pkey, test_case->name)
        && EVP_PKEY_get_security_bits(pkey) == test_case->security_bits;

done:
    printf("%s: %s\n", test_case->name, ok ? "PASS" : "FAIL");
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/*
 * Every composite KEM must be advertised, or none of them: the provider no
 * longer gates OSSL_OP_KEM on a runtime probe, so partial advertising would mean
 * the dispatch tables and the algorithm list had drifted apart.
 */
static int test_kem_operation_advertising_consistent(void)
{
    size_t i;

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        EVP_KEM *kem = EVP_KEM_fetch(NULL, test_cases[i].name,
                                     "provider=composite");

        if (kem == NULL) {
            printf("%s: FAIL (KEM operation not advertised)\n",
                   test_cases[i].name);
            ERR_print_errors_fp(stderr);
            return 0;
        }
        EVP_KEM_free(kem);
    }
    printf("all %zu composite KEMs advertised: PASS\n",
           sizeof(test_cases) / sizeof(test_cases[0]));
    return 1;
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
    if (ERR_peek_error() != 0) {
        fprintf(stderr, "provider load succeeded but left errors queued\n");
        ERR_print_errors_fp(stderr);
        composite_test_providers_unload(&providers);
        return 1;
    }

    ok = test_kem_operation_advertising_consistent();

    if (!composite_test_mlkem_available()) {
        printf("test_evp_kem_keygen: SKIP (no ML-KEM-768/1024 in this "
               "OpenSSL build)\n");
        composite_test_providers_unload(&providers);
        return ok ? COMPOSITE_TEST_SKIP : 1;
    }

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        ok &= test_algorithm(&test_cases[i]);

    composite_test_providers_unload(&providers);
    return ok ? 0 : 1;
}
