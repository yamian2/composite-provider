#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#include "composite_kem_info.h"

typedef struct {
    const char *name;
    const char *mlkem_ss_hex;
    const char *trad_ss_hex;
    const char *trad_ct_hex;
    const char *trad_pk_hex;
    const char *expected_ss_hex;
} COMBINER_VECTOR;

/*
 * Verbatim from draft-ietf-lamps-pq-composite-kem-18, Appendix F ("Examples of
 * KEM Combiner Intermediate Values"), Examples 1-3. Appendix F publishes exactly
 * these three, so this covers every combiner example in the draft.
 *
 * Note the X25519 label really is the six bytes 5c2e2f2f5e5c ("\.//^\") rather
 * than an "MLKEM768-X25519" string - that is what the draft specifies, and it is
 * the one entry that breaks the naming pattern. Do not "fix" it.
 */
static const COMBINER_VECTOR vectors[] = {
    {
        MLKEM768_P256_SN,
        "ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43",
        "ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0",
        "041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d1917127"
        "0cdefcd4abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5"
        "e7610",
        "04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159f"
        "f73d38d29aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e803"
        "96a3e",
        "d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee"
    },
    {
        MLKEM768_X25519_SN,
        "461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1",
        "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843",
        "0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f",
        "1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b",
        "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98"
    },
    {
        MLKEM1024_P384_SN,
        "c0f87f0c53fa8e2ba192a494694d37d1e3cf99c65e0dc5f69b2cc044b3fb205d",
        "4d52b7ef430382f479603207c0b8f7aa5bc35d8758835007e39a2642ad"
        "65e635d674db7a5513889657fb24e4e228a098",
        "0401a5b81dcb51290a0eb142b9032d5a37503164b7a20ac0e3b52dc54f"
        "9b0b7c9fdd2699a59563a0b9ad0e54478846faeab72b92275e1fbb8b963bcc6e80e"
        "30c089fbe4ed8d47ec76951db94aede46e679d5692eeb1d1b150d5b2e6660dc67c4"
        "69",
        "0468cc4acc5dd85edbcbf25bae7ee7dcacec2968ea7ee57fc91311cb9c"
        "47d4a24c3854e5ce3e5d0b309fda493224520f2870496eb16571108b3deafd72c1d"
        "f17edc302fbb8b60bae44d93177e6df5278e4667a090a2d59a2076f41d693975e8d"
        "19",
        "eb60f6c80a309ad4158d7b02f2cf8c947faead96ebbd85c3f62a94868ffddca4"
    },
};

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char **out, size_t *out_len)
{
    size_t hex_len;
    size_t i;
    unsigned char *buf;

    if (hex == NULL || out == NULL || out_len == NULL)
        return 0;

    hex_len = strlen(hex);
    if ((hex_len % 2) != 0)
        return 0;

    buf = OPENSSL_malloc(hex_len / 2);
    if (buf == NULL)
        return 0;

    for (i = 0; i < hex_len / 2; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            OPENSSL_free(buf);
            return 0;
        }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }

    *out = buf;
    *out_len = hex_len / 2;
    return 1;
}

static int test_vector(const COMBINER_VECTOR *vector)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    unsigned char *mlkem_ss = NULL, *trad_ss = NULL;
    unsigned char *trad_ct = NULL, *trad_pk = NULL;
    unsigned char *expected_ss = NULL;
    size_t mlkem_ss_len = 0, trad_ss_len = 0;
    size_t trad_ct_len = 0, trad_pk_len = 0, expected_ss_len = 0;
    unsigned char actual_ss[32];
    size_t actual_ss_len = sizeof(actual_ss);
    int ok = 0;

    alg = composite_kem_alg_info_find(vector->name);
    if (alg == NULL)
        goto done;

    if (!hex_to_bytes(vector->mlkem_ss_hex, &mlkem_ss, &mlkem_ss_len)
            || !hex_to_bytes(vector->trad_ss_hex, &trad_ss, &trad_ss_len)
            || !hex_to_bytes(vector->trad_ct_hex, &trad_ct, &trad_ct_len)
            || !hex_to_bytes(vector->trad_pk_hex, &trad_pk, &trad_pk_len)
            || !hex_to_bytes(vector->expected_ss_hex, &expected_ss,
                             &expected_ss_len))
        goto done;

    if (expected_ss_len != sizeof(actual_ss))
        goto done;

    if (!composite_kem_combine_shared_secret(NULL, alg, mlkem_ss,
                                             mlkem_ss_len, trad_ss,
                                             trad_ss_len, trad_ct,
                                             trad_ct_len, trad_pk, trad_pk_len,
                                             actual_ss, &actual_ss_len))
        goto done;

    ok = actual_ss_len == expected_ss_len
        && memcmp(actual_ss, expected_ss, expected_ss_len) == 0;

done:
    printf("%s combiner vector: %s\n", vector->name, ok ? "PASS" : "FAIL");
    OPENSSL_free(mlkem_ss);
    OPENSSL_free(trad_ss);
    OPENSSL_free(trad_ct);
    OPENSSL_free(trad_pk);
    OPENSSL_free(expected_ss);
    return ok;
}

/*
 * EVP_DigestFinal_ex() always writes the full digest size, so the combiner must
 * refuse an output buffer smaller than final_ss_len before hashing rather than
 * noticing afterwards. Guard bytes catch a regression that writes first.
 */
static int test_short_output_buffer_rejected(void)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    unsigned char scratch[64];
    unsigned char zeros[32] = { 0 };
    size_t out_len;
    int ok = 0;

    alg = composite_kem_alg_info_find(MLKEM768_P256_SN);
    if (alg == NULL)
        goto done;

    memset(scratch, 0x5a, sizeof(scratch));
    out_len = alg->final_ss_len - 1;

    if (composite_kem_combine_shared_secret(NULL, alg, zeros, sizeof(zeros),
                                            zeros, sizeof(zeros), zeros,
                                            sizeof(zeros), zeros, sizeof(zeros),
                                            scratch, &out_len))
        goto done;

    /* Nothing at all may have been written. */
    for (out_len = 0; out_len < sizeof(scratch); out_len++) {
        if (scratch[out_len] != 0x5a)
            goto done;
    }
    ok = 1;

done:
    printf("combiner rejects short output buffer: %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
        ok &= test_vector(&vectors[i]);

    ok &= test_short_output_buffer_rejected();

    return ok ? 0 : 1;
}
