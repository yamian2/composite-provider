#ifndef _COMPOSITE_KEM_KEY_H
#define _COMPOSITE_KEM_KEY_H

#include "provider.h"

#include <openssl/evp.h>

BEGIN_C_DECLS

// ========================
// Composite Crypto Support
// ========================

// // Basic CTRL values for COMPOSITE support
// # define EVP_PKEY_CTRL_COMPOSITE_PUSH    0x201
// # define EVP_PKEY_CTRL_COMPOSITE_POP     0x202
// # define EVP_PKEY_CTRL_COMPOSITE_ADD     0x203
// # define EVP_PKEY_CTRL_COMPOSITE_DEL     0x204
// # define EVP_PKEY_CTRL_COMPOSITE_CLEAR   0x205

// ==============================
// Declarations & Data Structures
// ==============================

// typedef struct _composite_key_st {
//   int algorithm;
//   const EVP_MD * md;
//   EVP_PKEY * ml_dsa_key;
//   EVP_PKEY * trad_key;
// } COMPOSITE_KEY;

/*
 * Algorithm Identifiers for ML-KEM (FIPS 203)
 */
#define ML_KEM_768  4
#define ML_KEM_1024 5

/*
 * ML-KEM-1024 Size Definitions (FIPS 203)
 * Note: PRIV_KEY_SZ represents a compact representation (seed or hash), not the full
 * expanded private key. Full private key would be 3168 bytes.
 */
#define ML_KEM_1024_PUB_KEY_SZ  1568
#define ML_KEM_1024_PRIV_KEY_SZ 64
#define ML_KEM_1024_CT_SZ       1568

/*
 * ML-KEM-768 Size Definitions (FIPS 203)
 * Note: PRIV_KEY_SZ represents a compact representation (seed or hash), not the full
 * expanded private key. Full private key would be 2400 bytes.
 */
#define ML_KEM_768_PUB_KEY_SZ  1184
#define ML_KEM_768_PRIV_KEY_SZ 64
#define ML_KEM_768_CT_SZ       1088
#define ML_KEM_SS_SZ           32
#define COMPOSITE_KEM_SS_SIZE  32

/* Key context structure */
typedef struct composite_kemkey_st {

    // Composite context
    COMPOSITE_CTX *provctx;

    // Identifier for the algorithm used
    int nid;

    // Identifier for the name of the algorithm
    const char *composite_name;

    // Identifier for the TLS name of the algorithm
    const char *composite_tls_name;

    // ML-KEM component and context
    const char *mlkem_name;
    EVP_PKEY_CTX *ml_kem_ctx;
    EVP_PKEY *mlkem_key;

    /*
     * ML-KEM public and private keys.
     *
     * These fields own their EVP_PKEY references. If the same private-capable
     * EVP_PKEY is stored in both fields, the second assignment must first call
     * EVP_PKEY_up_ref().
     */
    void *mlkem_privkey;
    void *mlkem_pubkey;

    // Classic Algorithm name and context
    const char *classic_algorithm_name;
    EVP_PKEY_CTX *classic_ctx;
    EVP_PKEY *classic_key;

    /*
     * Classic Algorithm public and private keys.
     *
     * These fields own their EVP_PKEY references. get0 accessors return
     * borrowed pointers; set0 transfers ownership to COMPOSITE_KEM_KEY.
     */
    void *classic_privkey;
    void *classic_pubkey;

    int has_private;

} COMPOSITE_KEM_KEY;

// ====================
// Functions Prototypes
// ====================


/*! \brief Allocates the memory for a new Composite Key
*
* \return A pointer to the new Composite Key, or NULL on error.
*/
COMPOSITE_KEM_KEY * composite_kemkey_new(void);

/*!
 * \brief Generates the cryptographic key material for a Composite Key
 *
 * This function generates the key material for both the ML-KEM and
 * traditional components of the Composite Key based on the specified
 * algorithm.
 * 
 * \param[in out] key The Composite Key to generate key material for.
 * \param[in] algorithm The name of the composite algorithm to use.
 * \param[in] ctx The Composite context to use for key generation.
 *
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_generate(COMPOSITE_KEM_KEY * key,
                               const char       * const algorithm,
                               COMPOSITE_CTX    * ctx);

/*!
 * \brief Frees the memory associated with a Composite Key
 *
 * \param key The Composite Key to free.
 */
void composite_kemkey_free(COMPOSITE_KEM_KEY * key);

/*!
 * \brief Retrieves the components of a Composite Key
 *
 * This function retrieves the ML-KEM key and traditional key components of
 * a Composite Key. The returned pointers are only valid as long as the
 * Composite Key is not modified or freed (i.e., they are still owned by)
 * the Composite Key and the caller SHALL NOT free them.
 * 
 * \param[in] key The Composite Key to retrieve components from.
 * \param[out] ml_kem_key Pointer to store the ML-DSA key.
 * \param[out] trad_key Pointer to store the traditional key.
 * 
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_get0_components(const COMPOSITE_KEM_KEY  * const key, 
                                     EVP_PKEY                ** const ml_kem_key,
                                     EVP_PKEY                ** const trad_key);

EVP_PKEY *composite_kemkey_get0_mlkem_public(const COMPOSITE_KEM_KEY *key);
EVP_PKEY *composite_kemkey_get0_classic_public(const COMPOSITE_KEM_KEY *key);
EVP_PKEY *composite_kemkey_get0_mlkem_private(const COMPOSITE_KEM_KEY *key);
EVP_PKEY *composite_kemkey_get0_classic_private(const COMPOSITE_KEM_KEY *key);

/*!
 * \brief Import a composite private key from its draft §4.2 serialization.
 *
 * dk = mlkemSeed(64) || tradSK, where tradSK is a DER RSAPrivateKey (RFC 8017),
 * a DER ECPrivateKey (RFC 5915), or the raw X25519/X448 scalar.  Rebuilds both
 * component EVP_PKEYs (the classic public half is derived by OpenSSL from the
 * private material) and sets has_private.
 *
 * key->composite_name and key->provctx must already be set.
 *
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_import_private(COMPOSITE_KEM_KEY *key,
                                    const unsigned char *dk, size_t dk_len);

/*!
 * \brief Import a composite public key from its draft §4.1 serialization.
 *
 * ek = mlkemPK || tradPK, where tradPK is a DER RSAPublicKey, an uncompressed
 * X9.62 EC point, or the raw X25519/X448 public key.  Populates only the
 * public component slots; has_private is left at 0.
 *
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_import_public(COMPOSITE_KEM_KEY *key,
                                   const unsigned char *ek, size_t ek_len);

/*!
 * \brief Serialize the composite private key per draft §4.2
 *        (mlkemSeed(64) || tradSK).
 *
 * *out is OPENSSL_malloc'd key material: the caller must release it with
 * OPENSSL_clear_free(*out, *out_len).
 *
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_encode_private(const COMPOSITE_KEM_KEY *key,
                                    unsigned char **out, size_t *out_len);

/*!
 * \brief Serialize the composite public key per draft §4.1
 *        (mlkemPK || tradPK).  *out is OPENSSL_malloc'd; caller frees.
 *
 * \return 1 on success, 0 on failure.
 */
int composite_kemkey_encode_public(const COMPOSITE_KEM_KEY *key,
                                   unsigned char **out, size_t *out_len);

/*
 * Serialize the traditional component public key in its combiner (tradPK)
 * encoding: DER RSAPublicKey, uncompressed X9.62 point, or raw bytes.
 * Shared by encapsulation, decapsulation and export.  *out is
 * OPENSSL_malloc'd; caller frees.
 *
 * (Forward-declared struct: composite_kem_info.h includes this header, so the
 * full COMPOSITE_KEM_ALG_INFO definition cannot be pulled in here.)
 */
struct composite_kem_alg_info_st;
int composite_kemkey_serialize_trad_public(
        const struct composite_kem_alg_info_st *alg,
        EVP_PKEY *pkey, unsigned char **out, size_t *out_len);

/*
 * Build a traditional-component public EVP_PKEY from its wire encoding
 * (an uncompressed EC point, raw X25519/X448 bytes, or DER RSAPublicKey).
 * Used for public-key import and for reconstructing the sender's ephemeral
 * key from tradCT during decapsulation.
 */
EVP_PKEY *composite_kemkey_classic_pub_from_bytes(
        OSSL_LIB_CTX *libctx, const struct composite_kem_alg_info_st *alg,
        const unsigned char *buf, size_t len);

END_C_DECLS

#endif /* _COMPOSITE_SIG_KEY_H */
