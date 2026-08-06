#ifndef _COMPOSITE_TEST_H
#define _COMPOSITE_TEST_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "composite_provider.h"

/*
 * Exit code CTest is configured to read as "skipped" via SKIP_RETURN_CODE.
 * Returning 0 for a skipped test makes an untested code path indistinguishable
 * from a passing one.
 */
#define COMPOSITE_TEST_SKIP 77

typedef struct {
    OSSL_PROVIDER *deflt;
    OSSL_PROVIDER *composite;
} COMPOSITE_TEST_PROVIDERS;

/*
 * Load the default provider alongside the composite one.
 *
 * Explicitly activating any provider suppresses OpenSSL's implicit
 * default-provider fallback. Loading only "composite" therefore leaves a libctx
 * with no ML-KEM, EC or RSA - and the provider's child libctx mirrors that - so
 * every composite operation fails at the component step. Loading "composite"
 * alone is what silently kept the encapsulation path out of the test suite.
 */
static ossl_unused int composite_test_providers_load(COMPOSITE_TEST_PROVIDERS *p)
{
    p->deflt = OSSL_PROVIDER_load(NULL, "default");
    p->composite = OSSL_PROVIDER_load(NULL, "composite");
    if (p->deflt == NULL || p->composite == NULL) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

static ossl_unused void composite_test_providers_unload(
        COMPOSITE_TEST_PROVIDERS *p)
{
    if (p->composite != NULL)
        OSSL_PROVIDER_unload(p->composite);
    if (p->deflt != NULL)
        OSSL_PROVIDER_unload(p->deflt);
}

/*
 * The composite KEMs are advertised unconditionally, so a missing ML-KEM
 * component only surfaces when a component operation actually runs. Probe for it
 * so that "no ML-KEM in this OpenSSL build" reports as a skip, not a failure.
 */
static ossl_unused int composite_test_mlkem_available(void)
{
    EVP_PKEY_CTX *pctx768 = EVP_PKEY_CTX_new_from_name(NULL,
                                                       DEFAULT_MLKEM768_NAME,
                                                       NULL);
    EVP_PKEY_CTX *pctx1024 = EVP_PKEY_CTX_new_from_name(NULL,
                                                        DEFAULT_MLKEM1024_NAME,
                                                        NULL);
    int available = pctx768 != NULL && pctx1024 != NULL;

    EVP_PKEY_CTX_free(pctx768);
    EVP_PKEY_CTX_free(pctx1024);
    if (!available)
        ERR_clear_error();
    return available;
}

#endif /* _COMPOSITE_TEST_H */
