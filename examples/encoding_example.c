#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "composite_kem_encoding.h"

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++)
        printf("%02x", data[i]);
    if (len > 32)
        printf("...");
    printf("\n");
}

static int demo_kem_public_key_encoding(void)
{
    unsigned char pq_key[ML_KEM_768_PUB_KEY_SZ];
    unsigned char trad_key[128];
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t encoded_len = 0;
    size_t decoded_pq_len = 0;
    size_t decoded_trad_len = 0;
    int ok = 0;

    memset(pq_key, 0xA4, sizeof(pq_key));
    memset(trad_key, 0x5A, sizeof(trad_key));

    if (!composite_kem_pubkey_encode(ML_KEM_768,
                                     pq_key, sizeof(pq_key),
                                     trad_key, sizeof(trad_key),
                                     NULL, &encoded_len))
        goto done;

    encoded = malloc(encoded_len);
    if (encoded == NULL)
        goto done;

    if (!composite_kem_pubkey_encode(ML_KEM_768,
                                     pq_key, sizeof(pq_key),
                                     trad_key, sizeof(trad_key),
                                     encoded, &encoded_len))
        goto done;

    print_hex("Encoded KEM public key", encoded, encoded_len);

    if (!composite_kem_pubkey_decode(ML_KEM_768,
                                     encoded, encoded_len,
                                     &decoded_pq, &decoded_pq_len,
                                     &decoded_trad, &decoded_trad_len))
        goto done;

    ok = decoded_pq_len == sizeof(pq_key)
        && decoded_trad_len == sizeof(trad_key)
        && memcmp(decoded_pq, pq_key, sizeof(pq_key)) == 0
        && memcmp(decoded_trad, trad_key, sizeof(trad_key)) == 0;

done:
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    return ok;
}

static int demo_kem_ciphertext_encoding(void)
{
    unsigned char pq_ct[ML_KEM_768_CT_SZ];
    unsigned char trad_ct[133];
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t encoded_len = 0;
    size_t decoded_pq_len = 0;
    size_t decoded_trad_len = 0;
    int ok = 0;

    memset(pq_ct, 0xC2, sizeof(pq_ct));
    memset(trad_ct, 0x8D, sizeof(trad_ct));

    if (!composite_kem_ct_encode(ML_KEM_768,
                                 pq_ct, sizeof(pq_ct),
                                 trad_ct, sizeof(trad_ct),
                                 NULL, &encoded_len))
        goto done;

    encoded = malloc(encoded_len);
    if (encoded == NULL)
        goto done;

    if (!composite_kem_ct_encode(ML_KEM_768,
                                 pq_ct, sizeof(pq_ct),
                                 trad_ct, sizeof(trad_ct),
                                 encoded, &encoded_len))
        goto done;

    print_hex("Encoded KEM ciphertext", encoded, encoded_len);

    if (!composite_kem_ct_decode(ML_KEM_768,
                                 encoded, encoded_len,
                                 &decoded_pq, &decoded_pq_len,
                                 &decoded_trad, &decoded_trad_len))
        goto done;

    ok = decoded_pq_len == sizeof(pq_ct)
        && decoded_trad_len == sizeof(trad_ct)
        && memcmp(decoded_pq, pq_ct, sizeof(pq_ct)) == 0
        && memcmp(decoded_trad, trad_ct, sizeof(trad_ct)) == 0;

done:
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    return ok;
}

int main(void)
{
    printf("=== Composite KEM Encoding Example ===\n\n");

    if (!demo_kem_public_key_encoding()) {
        fprintf(stderr, "KEM public key encoding example failed\n");
        return 1;
    }
    printf("KEM public key encoding/decoding successful\n\n");

    if (!demo_kem_ciphertext_encoding()) {
        fprintf(stderr, "KEM ciphertext encoding example failed\n");
        return 1;
    }
    printf("KEM ciphertext encoding/decoding successful\n");

    return 0;
}
