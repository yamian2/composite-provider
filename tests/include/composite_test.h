#ifndef _COMPOSITE_TEST_H
#define _COMPOSITE_TEST_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <string.h>

#include "composite_provider.h"

/*
 * Exit code CTest is configured to read as "skipped" via SKIP_RETURN_CODE.
 * Returning 0 for a skipped test makes an untested code path indistinguishable
 * from a passing one.
 */
#define COMPOSITE_TEST_SKIP 77

/* Every composite KEM produces a 32-byte shared secret (draft §3.4). */
#define COMPOSITE_TEST_KEM_SS_LEN 32

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

/*
 * Decode a base64 test vector.
 *
 * The generated header stores vectors base64 rather than hex because that is
 * the source file's encoding; converting at generation time would let this
 * decoder and the generator disagree silently.
 *
 * EVP_DecodeBlock is deliberately not used: it pads the output to a multiple
 * of three and does not report how many of those bytes were padding, so a
 * 32-byte shared secret comes back as 33 and the comparison against k fails
 * for a reason that looks like a cryptographic error.  EVP_DecodeUpdate with
 * newline-insensitive input gives the exact length.
 *
 * Returns a malloc'd buffer the caller frees with OPENSSL_free, or NULL.
 */
static ossl_unused unsigned char *composite_test_b64(const char *in,
                                                     size_t *out_len)
{
    EVP_ENCODE_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    size_t in_len;
    int len = 0, final = 0;

    if (in == NULL || out_len == NULL)
        return NULL;
    in_len = strlen(in);

    /* 3 bytes out per 4 in, plus slack for the decoder's block handling. */
    buf = OPENSSL_malloc(in_len / 4 * 3 + 4);
    ctx = EVP_ENCODE_CTX_new();
    if (buf == NULL || ctx == NULL)
        goto err;

    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, buf, &len, (const unsigned char *)in,
                         (int)in_len) < 0)
        goto err;
    if (EVP_DecodeFinal(ctx, buf + len, &final) < 0)
        goto err;

    EVP_ENCODE_CTX_free(ctx);
    *out_len = (size_t)len + (size_t)final;
    return buf;

err:
    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_free(buf);
    *out_len = 0;
    return NULL;
}

#endif /* _COMPOSITE_TEST_H */
