#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>

#include "composite_kem_key.h"

typedef struct {
    const char *composite_name;
    const char *mlkem_name;
    const char *classic_name;
    int classic_bits;
    const char *classic_group;
} KEM_TEST_CASE;

static const KEM_TEST_CASE test_cases[] = {
    { MLKEM768_RSA2048_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 2048, NULL },
    { MLKEM768_RSA3072_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 3072, NULL },
    { MLKEM768_RSA4096_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 4096, NULL },
    { MLKEM768_X25519_SN, DEFAULT_MLKEM768_NAME, "X25519", 0, NULL },
    { MLKEM768_P256_SN, DEFAULT_MLKEM768_NAME, "EC", 256, "prime256v1" },
    { MLKEM768_P384_SN, DEFAULT_MLKEM768_NAME, "EC", 384, "secp384r1" },
    { MLKEM768_BRAINPOOLP256_SN, DEFAULT_MLKEM768_NAME, "EC", 256, "brainpoolP256r1" },
    { MLKEM1024_RSA3072_SN, DEFAULT_MLKEM1024_NAME, DEFAULT_RSA_NAME, 3072, NULL },
    { MLKEM1024_P384_SN, DEFAULT_MLKEM1024_NAME, "EC", 384, "secp384r1" },
    { MLKEM1024_BRAINPOOLP384_SN, DEFAULT_MLKEM1024_NAME, "EC", 384, "brainpoolP384r1" },
    { MLKEM1024_X448_SN, DEFAULT_MLKEM1024_NAME, "X448", 0, NULL },
    { MLKEM1024_P521_SN, DEFAULT_MLKEM1024_NAME, "EC", 521, "secp521r1" },
};

static int mlkem_components_available(COMPOSITE_CTX *ctx)
{
    EVP_PKEY_CTX *pctx768 = NULL;
    EVP_PKEY_CTX *pctx1024 = NULL;
    int available;

    pctx768 = EVP_PKEY_CTX_new_from_name(ctx->libctx, DEFAULT_MLKEM768_NAME,
                                         NULL);
    pctx1024 = EVP_PKEY_CTX_new_from_name(ctx->libctx, DEFAULT_MLKEM1024_NAME,
                                          NULL);
    available = pctx768 != NULL && pctx1024 != NULL;
    EVP_PKEY_CTX_free(pctx768);
    EVP_PKEY_CTX_free(pctx1024);
    if (!available)
        ERR_clear_error();
    return available;
}

static int test_invalid_arguments(COMPOSITE_CTX *ctx)
{
    COMPOSITE_KEM_KEY *key = composite_kemkey_new();
    int ok = key != NULL
        && !composite_kemkey_generate(NULL, MLKEM768_RSA2048_SN, ctx)
        && !composite_kemkey_generate(key, NULL, ctx)
        && !composite_kemkey_generate(key, "not-a-composite-kem", ctx)
        && !composite_kemkey_generate(key, MLKEM768_RSA2048_SN, NULL);

    ERR_clear_error();
    composite_kemkey_free(key);
    return ok;
}

static int test_algorithm(COMPOSITE_CTX *ctx, const KEM_TEST_CASE *test_case)
{
    COMPOSITE_KEM_KEY *key = composite_kemkey_new();
    EVP_PKEY *mlkem = NULL;
    EVP_PKEY *classic = NULL;
    char group[80] = { 0 };
    size_t group_len = 0;
    int ok = 0;

    if (key == NULL
            || !composite_kemkey_generate(key, test_case->composite_name, ctx)
            || !composite_kemkey_get0_components(key, &mlkem, &classic))
        goto done;

    ok = mlkem != NULL && classic != NULL
        && EVP_PKEY_is_a(mlkem, test_case->mlkem_name)
        && EVP_PKEY_is_a(classic, test_case->classic_name);
    if (ok && test_case->classic_bits != 0)
        ok = EVP_PKEY_get_bits(classic) == test_case->classic_bits;
    if (ok && test_case->classic_group != NULL) {
        ok = EVP_PKEY_get_utf8_string_param(classic, OSSL_PKEY_PARAM_GROUP_NAME,
                                            group, sizeof(group), &group_len)
            && strcmp(group, test_case->classic_group) == 0;
    }

done:
    printf("%s: %s\n", test_case->composite_name, ok ? "PASS" : "FAIL");
    if (!ok)
        ERR_print_errors_fp(stderr);
    composite_kemkey_free(key);
    return ok;
}

int main(void)
{
    COMPOSITE_CTX ctx = { 0 };
    size_t i;
    int ok = 1;
    int components_available;

    ctx.libctx = OSSL_LIB_CTX_new();
    if (ctx.libctx == NULL)
        return 1;

    ok &= test_invalid_arguments(&ctx);
    components_available = mlkem_components_available(&ctx);
    if (!components_available) {
        printf("Composite KEM keygen positive cases: SKIP "
               "(ML-KEM components unavailable)\n");
        OSSL_LIB_CTX_free(ctx.libctx);
        return ok ? 0 : 1;
    }

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        ok &= test_algorithm(&ctx, &test_cases[i]);

    OSSL_LIB_CTX_free(ctx.libctx);
    return ok ? 0 : 1;
}
