#include "composite_kem_info.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <string.h>

#define MLKEM_SS_LEN 32
#define COMPOSITE_FINAL_SS_LEN 32

static const unsigned char label_mlkem768_rsa2048[] =
    "MLKEM768-RSAOAEP2048";
static const unsigned char label_mlkem768_rsa3072[] =
    "MLKEM768-RSAOAEP3072";
static const unsigned char label_mlkem768_rsa4096[] =
    "MLKEM768-RSAOAEP4096";
static const unsigned char label_mlkem768_x25519[] = {
    0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
};
static const unsigned char label_mlkem768_p256[] = "MLKEM768-P256";
static const unsigned char label_mlkem768_p384[] = "MLKEM768-P384";
static const unsigned char label_mlkem768_brainpoolp256[] = "MLKEM768-BP256";
static const unsigned char label_mlkem1024_rsa3072[] =
    "MLKEM1024-RSAOAEP3072";
static const unsigned char label_mlkem1024_p384[] = "MLKEM1024-P384";
static const unsigned char label_mlkem1024_brainpoolp384[] = "MLKEM1024-BP384";
static const unsigned char label_mlkem1024_x448[] = "MLKEM1024-X448";
static const unsigned char label_mlkem1024_p521[] = "MLKEM1024-P521";

#define LABEL_INFO(label_name) label_name, sizeof(label_name) - 1

static const COMPOSITE_KEM_ALG_INFO kem_algorithms[] = {
    { MLKEM768_RSA2048_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, DEFAULT_RSA_NAME,
      COMP_KEM_TRAD_RSA_OAEP, 2048, 256, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem768_rsa2048) },
    { MLKEM768_RSA3072_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, DEFAULT_RSA_NAME,
      COMP_KEM_TRAD_RSA_OAEP, 3072, 384, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem768_rsa3072) },
    { MLKEM768_RSA4096_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, DEFAULT_RSA_NAME,
      COMP_KEM_TRAD_RSA_OAEP, 4096, 512, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem768_rsa4096) },
    { MLKEM768_X25519_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, "X25519",
      COMP_KEM_TRAD_X25519, 0, 32, COMPOSITE_FINAL_SS_LEN,
      label_mlkem768_x25519, sizeof(label_mlkem768_x25519) },
    { MLKEM768_P256_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_X9_62_prime256v1, 65,
      COMPOSITE_FINAL_SS_LEN, LABEL_INFO(label_mlkem768_p256) },
    { MLKEM768_P384_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_secp384r1, 97, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem768_p384) },
    { MLKEM768_BRAINPOOLP256_SN, DEFAULT_MLKEM768_NAME, ML_KEM_768,
      ML_KEM_768_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_brainpoolP256r1, 65,
      COMPOSITE_FINAL_SS_LEN, LABEL_INFO(label_mlkem768_brainpoolp256) },
    { MLKEM1024_RSA3072_SN, DEFAULT_MLKEM1024_NAME, ML_KEM_1024,
      ML_KEM_1024_CT_SZ, MLKEM_SS_LEN, DEFAULT_RSA_NAME,
      COMP_KEM_TRAD_RSA_OAEP, 3072, 384, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem1024_rsa3072) },
    { MLKEM1024_P384_SN, DEFAULT_MLKEM1024_NAME, ML_KEM_1024,
      ML_KEM_1024_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_secp384r1, 97, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem1024_p384) },
    { MLKEM1024_BRAINPOOLP384_SN, DEFAULT_MLKEM1024_NAME, ML_KEM_1024,
      ML_KEM_1024_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_brainpoolP384r1, 97,
      COMPOSITE_FINAL_SS_LEN, LABEL_INFO(label_mlkem1024_brainpoolp384) },
    { MLKEM1024_X448_SN, DEFAULT_MLKEM1024_NAME, ML_KEM_1024,
      ML_KEM_1024_CT_SZ, MLKEM_SS_LEN, "X448",
      COMP_KEM_TRAD_X448, 0, 56, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem1024_x448) },
    { MLKEM1024_P521_SN, DEFAULT_MLKEM1024_NAME, ML_KEM_1024,
      ML_KEM_1024_CT_SZ, MLKEM_SS_LEN, "EC",
      COMP_KEM_TRAD_ECDH, NID_secp521r1, 133, COMPOSITE_FINAL_SS_LEN,
      LABEL_INFO(label_mlkem1024_p521) },
};

const COMPOSITE_KEM_ALG_INFO *composite_kem_alg_info_find(
        const char *composite_name)
{
    size_t i;

    if (composite_name == NULL)
        return NULL;

    for (i = 0; i < sizeof(kem_algorithms) / sizeof(kem_algorithms[0]); i++) {
        if (strcmp(kem_algorithms[i].composite_name, composite_name) == 0)
            return &kem_algorithms[i];
    }
    return NULL;
}

int composite_kem_combine_shared_secret(OSSL_LIB_CTX *libctx,
                                        const COMPOSITE_KEM_ALG_INFO *alg,
                                        const unsigned char *mlkem_ss,
                                        size_t mlkem_ss_len,
                                        const unsigned char *trad_ss,
                                        size_t trad_ss_len,
                                        const unsigned char *trad_ct,
                                        size_t trad_ct_len,
                                        const unsigned char *trad_pk,
                                        size_t trad_pk_len,
                                        unsigned char *out,
                                        size_t *out_len)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    /*
     * Digest into a local buffer rather than straight into "out": the caller
     * only guarantees final_ss_len bytes, while EVP_DigestFinal_ex() always
     * writes the full digest size. Copying out afterwards keeps the size check
     * ahead of the write instead of behind it.
     */
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int ret = 0;

    if (alg == NULL || mlkem_ss == NULL || trad_ss == NULL
            || trad_ct == NULL || trad_pk == NULL || out == NULL
            || out_len == NULL || *out_len < alg->final_ss_len)
        return 0;

    md = EVP_MD_fetch(libctx, "SHA3-256", NULL);
    mctx = EVP_MD_CTX_new();
    if (md == NULL || mctx == NULL)
        goto done;

    if (EVP_DigestInit_ex2(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, mlkem_ss, mlkem_ss_len) <= 0
            || EVP_DigestUpdate(mctx, trad_ss, trad_ss_len) <= 0
            || EVP_DigestUpdate(mctx, trad_ct, trad_ct_len) <= 0
            || EVP_DigestUpdate(mctx, trad_pk, trad_pk_len) <= 0
            || EVP_DigestUpdate(mctx, alg->label, alg->label_len) <= 0
            || EVP_DigestFinal_ex(mctx, digest, &digest_len) <= 0)
        goto done;

    if (digest_len != alg->final_ss_len)
        goto done;
    memcpy(out, digest, alg->final_ss_len);
    *out_len = alg->final_ss_len;
    ret = 1;

done:
    OPENSSL_cleanse(digest, sizeof(digest));
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    return ret;
}
