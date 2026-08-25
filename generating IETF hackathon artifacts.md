# Generating IETF Hackathon Artifacts

This note explains how to add composite KEM artifacts for this provider alongside
the existing signature artifacts in:

```text
/Users/jake/workspace/pqc-certificates/providers/composite-crypto
```

The existing directory currently contains the composite signature R5 files:

```text
<friendly>-<oid>_ta.der
<friendly>-<oid>_priv.der
artifacts_certs_r5.zip
```

For composite KEM, the local `pqc-certificates` reference provider uses this
shape instead:

```text
<name>-<oid>_ee.der
<name>-<oid>_priv.der
<name>-<oid>_priv.raw
<name>-<oid>_ciphertext.bin
<name>-<oid>_ss.bin
```

The important difference is that KEM public keys cannot self-sign certificates.
The KEM certificate is an end-entity certificate (`_ee.der`) whose
SubjectPublicKeyInfo contains the KEM public key. It must be signed by a
separate signing CA. For the R5 certificate artifacts, the generator signs each
KEM EE certificate with an ML-DSA TA at the equivalent ML-KEM security level.

## Current Repo Support

This provider already has the implementation pieces needed for KEM artifact
generation:

- `CMakeLists.txt` requires OpenSSL 3.5 or newer, which is necessary for
  built-in `ML-KEM-768` and `ML-KEM-1024`.
- `src/common/composite_provider.h` defines the 12 composite KEM names and OIDs.
- `src/kem/composite_kem_encoder.c` implements DER and PEM encoders for:
  `PrivateKeyInfo` and `SubjectPublicKeyInfo`.
- `src/kem/composite_kem_decoder.c` implements DER decoders for:
  `PrivateKeyInfo` and `SubjectPublicKeyInfo`.
- `tests/test_evp_kem_keygen.c` verifies key generation for all 12 KEMs.
- `tests/test_evp_kem_encaps.c` verifies encapsulation and ciphertext sizes.
- `tests/test_kem_codec_roundtrip.c` verifies PKCS#8/SPKI export/import against
  KEM test vectors when `tests/data/composite_kem_testvectors.json` is present.

`scripts/gen_composite_r5.sh` now generates both the composite signature
artifacts and the composite KEM artifacts into the same
`artifacts_certs_r5.zip`.

## KEM Algorithms

Generate artifacts for these 12 algorithms:

| OpenSSL algorithm name | File prefix | OID |
| --- | --- | --- |
| `id-MLKEM768-RSA2048-SHA3-256` | `id-MLKEM768-RSA2048-SHA3-256` | `1.3.6.1.5.5.7.6.55` |
| `id-MLKEM768-RSA3072-SHA3-256` | `id-MLKEM768-RSA3072-SHA3-256` | `1.3.6.1.5.5.7.6.56` |
| `id-MLKEM768-RSA4096-SHA3-256` | `id-MLKEM768-RSA4096-SHA3-256` | `1.3.6.1.5.5.7.6.57` |
| `id-MLKEM768-X25519-SHA3-256` | `id-MLKEM768-X25519-SHA3-256` | `1.3.6.1.5.5.7.6.58` |
| `id-MLKEM768-ECDH-P256-SHA3-256` | `id-MLKEM768-ECDH-P256-SHA3-256` | `1.3.6.1.5.5.7.6.59` |
| `id-MLKEM768-ECDH-P384-SHA3-256` | `id-MLKEM768-ECDH-P384-SHA3-256` | `1.3.6.1.5.5.7.6.60` |
| `id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256` | `id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256` | `1.3.6.1.5.5.7.6.61` |
| `id-MLKEM1024-RSA3072-SHA3-256` | `id-MLKEM1024-RSA3072-SHA3-256` | `1.3.6.1.5.5.7.6.62` |
| `id-MLKEM1024-ECDH-P384-SHA3-256` | `id-MLKEM1024-ECDH-P384-SHA3-256` | `1.3.6.1.5.5.7.6.63` |
| `id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256` | `id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256` | `1.3.6.1.5.5.7.6.64` |
| `id-MLKEM1024-X448-SHA3-256` | `id-MLKEM1024-X448-SHA3-256` | `1.3.6.1.5.5.7.6.65` |
| `id-MLKEM1024-ECDH-P521-SHA3-256` | `id-MLKEM1024-ECDH-P521-SHA3-256` | `1.3.6.1.5.5.7.6.66` |

## Build Prerequisite

Build OpenSSL and the provider first:

```sh
cd /Users/jake/workspace/composite-provider
./scripts/build_and_test.sh
```

That script creates:

```text
/Users/jake/workspace/composite-provider/openssl/apps/openssl
/Users/jake/workspace/composite-provider/_build/composite.dylib
```

On Linux the module suffix will be `.so`; on macOS it is `.dylib`.

For manual commands, use:

```sh
export OPENSSL_DIR=/Users/jake/workspace/composite-provider/openssl
export OPENSSL_BIN="$OPENSSL_DIR/apps/openssl"
export OPENSSL_MODULES=/Users/jake/workspace/composite-provider/_build
export OPENSSL_CONF=/Users/jake/workspace/composite-provider/tests/composite.cnf
export LD_LIBRARY_PATH="$OPENSSL_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

## Generation Flow

`scripts/gen_composite_r5.sh` now performs these steps.

1. Generate the 18 composite signature TA certificates and private keys.
2. Generate one KEM keypair per composite KEM algorithm using
   `openssl genpkey`.
3. Export the KEM private key as DER `PrivateKeyInfo`.
4. Extract the raw draft KEM private-key bytes into `_priv.raw`.
5. Export the KEM public key as PEM for use with `openssl x509 -force_pubkey`.
6. Select the equivalent-level ML-DSA TA for the KEM algorithm.
7. Create an EE certificate signed by that ML-DSA TA.
8. Encapsulate with the EE public key and save the ciphertext and shared secret.
9. Zip the generated `.der`, `.bin`, and `.raw` files into
   `artifacts_certs_r5.zip`.

The core loop should look like this:

```sh
for entry in "${COMPOSITE_KEM_ALGOS[@]}"; do
    read -r ossl_name friendly oid signer_oid <<< "${entry}"

    file_base="${friendly}-${oid}"
    kem_key="${WORK_DIR}/${file_base}.pem"
    kem_pub="${WORK_DIR}/${file_base}_pub.pem"
    ee_file="${STAGING_DIR}/${file_base}_ee.der"
    priv_file="${STAGING_DIR}/${file_base}_priv.der"
    ct_file="${STAGING_DIR}/${file_base}_ciphertext.bin"
    ss_file="${STAGING_DIR}/${file_base}_ss.bin"

    "${OPENSSL_BIN}" genpkey \
        -algorithm "${ossl_name}" \
        -out "${kem_key}"

    "${OPENSSL_BIN}" pkey \
        -in "${kem_key}" \
        -pubout \
        -out "${kem_pub}"

    "${OPENSSL_BIN}" pkey \
        -in "${kem_key}" \
        -outform DER \
        -out "${priv_file}"

    "${OPENSSL_BIN}" x509 -new \
        -outform DER \
        -out "${ee_file}" \
        -CAform DER \
        -CA "${SIGNING_TA_DER}" \
        -CAkey "${SIGNING_TA_KEY}" \
        -CAkeyform "${SIGNING_TA_KEYFORM}" \
        -force_pubkey "${kem_pub}" \
        -days 3650 \
        -subj "/" \
        -extfile "${WORK_DIR}/${file_base}.ext"

    "${OPENSSL_BIN}" pkeyutl \
        -encap \
        -inkey "${kem_pub}" \
        -out "${ct_file}" \
        -secret "${ss_file}"
done
```

The extension file used by `openssl x509` should be generated per algorithm:

```text
subjectKeyIdentifier=none
subjectAltName=critical,DNS:<friendly>.ee.example
basicConstraints=critical,CA:false
keyUsage=critical,keyEncipherment
```

Do not use `openssl req -new -x509` for the KEM key itself. The KEM key cannot
sign. Use `openssl x509 -new -force_pubkey` and sign with a separate ML-DSA TA
key.

## Signing CA Choice

The R5 README says to use the ML-DSA TA of the equivalent security level for
ML-KEM EE certificates. `scripts/gen_composite_r5.sh` therefore generates all
signature TAs first and then maps each KEM OID to the appropriate TA OID:

| KEM family | Signing TA family |
| - | - |
| ML-KEM-768 composite KEMs | ML-DSA-65 composite signature TAs |
| ML-KEM-1024 composite KEMs | ML-DSA-87 composite signature TAs |

Where the R5 signature OID set has a natural matching traditional component,
the generator uses that matching TA. The `id-MLKEM768-RSA2048-SHA3-256` KEM has
no `MLDSA65-RSA2048` signature TA in the R5 OID set, so it chains to the
`MLDSA65-RSA3072-PSS-SHA512` TA as the available level-3 ML-DSA TA.

## Raw Private Key

The reference KEM artifacts include `<name>-<oid>_priv.raw`, which is the raw
draft private key material (`dk = mlkemSeed || tradSK`) before PKCS#8 wrapping.
The generator emits this by extracting the PKCS#8 privateKey OCTET STRING from
the generated `_priv.der` with `openssl asn1parse` and `xxd`.

## Verification

After generation, verify the provider advertises all KEMs:

```sh
"${OPENSSL_BIN}" list -kem-algorithms -provider composite -provider default
```

Run the existing KEM tests:

```sh
cd /Users/jake/workspace/composite-provider
OPENSSL_MODULES="$PWD/_build" ./_build/tests/test_evp_kem_keygen
OPENSSL_MODULES="$PWD/_build" ./_build/tests/test_evp_kem_encaps
```

For each generated KEM artifact, verify these three properties:

1. `_ee.der` is parseable and exposes a public key.
2. `_priv.der` exports the same public key as `_ee.der`.
3. `_priv.der` decapsulates `_ciphertext.bin` to exactly `_ss.bin`.

Manual verification for one algorithm:

```sh
base="id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59"
dir="/Users/jake/workspace/pqc-certificates/providers/composite-crypto"

"${OPENSSL_BIN}" x509 \
    -inform DER \
    -in "${dir}/${base}_ee.der" \
    -pubkey \
    -noout \
    -out /tmp/kem-ee-pub.pem

"${OPENSSL_BIN}" pkey \
    -inform DER \
    -in "${dir}/${base}_priv.der" \
    -pubout \
    -out /tmp/kem-priv-pub.pem

diff /tmp/kem-ee-pub.pem /tmp/kem-priv-pub.pem

"${OPENSSL_BIN}" pkeyutl \
    -decap \
    -inkey "${dir}/${base}_priv.der" \
    -keyform DER \
    -in "${dir}/${base}_ciphertext.bin" \
    -secret /tmp/kem-ss.bin

diff /tmp/kem-ss.bin "${dir}/${base}_ss.bin"
```

The `pqc-certificates` repo also has a broader OpenSSL R5 verifier at:

```text
/Users/jake/workspace/pqc-certificates/src/test_certs_r5_openssl.sh
```

That script already knows about `_ee.der`, `_ciphertext.bin`, `_ss.bin`, and KEM
private-key decapsulation.

## Scripts To Enhance

These are the concrete scripts involved in this repo:

| File | Role |
| --- | --- |
| `scripts/gen_composite_r5.sh` | Generates 18 composite signature `_ta.der` and `_priv.der` files plus 12 composite KEM `_ee.der`, `_priv.der`, `_priv.raw`, `_ciphertext.bin`, and `_ss.bin` file sets. |
| `scripts/check_composite_r5.sh` | Verifies signature TA/private-key artifacts and KEM EE/consistency/private-key artifacts. |
| `scripts/test_all_providers.sh` | Iterates provider zips and builds compatibility CSVs for signature OIDs `.37` to `.54` and KEM OIDs `.55` to `.66`. |
| `scripts/README.md` | Documents the script workflows. |

## Submission Checklist

1. Build OpenSSL 3.5+ and the provider.
2. Run the combined signature and KEM generator into the provider directory:

   ```sh
   ./scripts/gen_composite_r5.sh /Users/jake/workspace/pqc-certificates/providers/composite-crypto
   ```

3. The script recreates `artifacts_certs_r5.zip` from the complete generated
   artifact set and copies the generated leaf files into the same directory.

4. Generate the CMS KEMRecipientInfo artifacts required by the MTI KDF section:

   ```sh
   ./scripts/gen_composite_cms_v3.sh /Users/jake/workspace/pqc-certificates/providers/composite-crypto
   ```

   This creates `artifacts_cms_v3.zip` with HKDF-SHA256 KEMRI artifacts for each
   composite KEM OID. The CMS zip reuses the KEM private keys, but issues
   CMS-specific KEM EE certificates under the included ML-DSA-44 `ta.der`.

5. Verify the zips with this provider and, if possible, with
   `/Users/jake/workspace/pqc-certificates/src/test_certs_r5_openssl.sh` and
   `/Users/jake/workspace/pqc-certificates/src/test_cms_v3_openssl.sh`.
