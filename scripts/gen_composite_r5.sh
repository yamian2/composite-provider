#!/usr/bin/env bash
# gen_composite_r5.sh
#
# Generates artifacts_certs_r5.zip for all 18 composite signature algorithms
# and all 12 composite KEM algorithms.
# following the IETF Hackathon R5 artifact naming convention:
#   <friendly>-<oid>_ta.der    — self-signed DER CA certificate (10-year)
#   <friendly>-<oid>_priv.der  — PKCS#8 DER private key
#
# Composite KEM outputs:
#   <friendly>-<oid>_ee.der          — DER EE certificate carrying KEM SPKI,
#                                      signed by the equivalent-level ML-DSA TA
#   <friendly>-<oid>_priv.der        — PKCS#8 DER private key
#   <friendly>-<oid>_priv.raw        — raw draft private key bytes
#   <friendly>-<oid>_ciphertext.bin  — encapsulated ciphertext
#   <friendly>-<oid>_ss.bin          — shared secret from encapsulation
#
# Example output filenames:
#   mldsa44_rsa2048_pss_sha256-1.3.6.1.5.5.7.6.37_ta.der
#   mldsa44_rsa2048_pss_sha256-1.3.6.1.5.5.7.6.37_priv.der
#
# Usage:
#   ./gen_composite_r5.sh [output_dir]
#
# The zip is written to <output_dir>/artifacts_certs_r5.zip
# Default output_dir: the directory containing this script.
#
# Environment variables (all optional):
#   OPENSSL_DIR   — OpenSSL build directory (default: workspace root)
#   OPENSSL_BIN   — Path to openssl binary  (default: OPENSSL_DIR/apps/openssl)
#   OPENSSL_CONF  — Path to openssl.cnf

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── OpenSSL binary configuration ────────────────────────────────────────────
OPENSSL_DIR="${OPENSSL_DIR:-${WORKSPACE_ROOT}/openssl}"
OPENSSL_BIN="${OPENSSL_BIN:-${OPENSSL_DIR}/apps/openssl}"
export LD_LIBRARY_PATH="${OPENSSL_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export OPENSSL_MODULES="${OPENSSL_MODULES:-${WORKSPACE_ROOT}/_build}"
OPENSSL_CONF="${OPENSSL_CONF:-${WORKSPACE_ROOT}/tests/composite.cnf}"
export OPENSSL_CONF

# ─── Output directory ────────────────────────────────────────────────────────
OUTPUT_DIR="${1:-${SCRIPT_DIR}}"
mkdir -p "${OUTPUT_DIR}"

if ! command -v xxd >/dev/null 2>&1; then
    echo "ERROR: xxd is required to extract KEM _priv.raw files."
    exit 1
fi

# ─── All 18 composite algorithms ─────────────────────────────────────────────
# Format per entry: "OPENSSL_GENPKEY_NAME  r5_friendly_prefix  oid"
# OPENSSL_GENPKEY_NAME uses the LN (long name) format registered by the provider.
COMPOSITE_ALGOS=(
    "MLDSA44-RSA2048-PSS-SHA256            mldsa44_rsa2048_pss_sha256             1.3.6.1.5.5.7.6.37"
    "MLDSA44-RSA2048-PKCS15-SHA256         mldsa44_rsa2048_pkcs15_sha256          1.3.6.1.5.5.7.6.38"
    "MLDSA44-Ed25519-SHA512                mldsa44_ed25519_sha512                 1.3.6.1.5.5.7.6.39"
    "MLDSA44-ECDSA-P256-SHA256             mldsa44_ecdsa_p256_sha256              1.3.6.1.5.5.7.6.40"
    "MLDSA65-RSA3072-PSS-SHA512            mldsa65_rsa3072_pss_sha512             1.3.6.1.5.5.7.6.41"
    "MLDSA65-RSA3072-PKCS15-SHA512         mldsa65_rsa3072_pkcs15_sha512          1.3.6.1.5.5.7.6.42"
    "MLDSA65-RSA4096-PSS-SHA512            mldsa65_rsa4096_pss_sha512             1.3.6.1.5.5.7.6.43"
    "MLDSA65-RSA4096-PKCS15-SHA512         mldsa65_rsa4096_pkcs15_sha512          1.3.6.1.5.5.7.6.44"
    "MLDSA65-ECDSA-P256-SHA512             mldsa65_ecdsa_p256_sha512              1.3.6.1.5.5.7.6.45"
    "MLDSA65-ECDSA-P384-SHA512             mldsa65_ecdsa_p384_sha512              1.3.6.1.5.5.7.6.46"
    "MLDSA65-ECDSA-brainpoolP256r1-SHA512  mldsa65_ecdsa_brainpoolp256r1_sha512   1.3.6.1.5.5.7.6.47"
    "MLDSA65-Ed25519-SHA512                mldsa65_ed25519_sha512                 1.3.6.1.5.5.7.6.48"
    "MLDSA87-ECDSA-P384-SHA512             mldsa87_ecdsa_p384_sha512              1.3.6.1.5.5.7.6.49"
    "MLDSA87-ECDSA-brainpoolP384r1-SHA512  mldsa87_ecdsa_brainpoolp384r1_sha512   1.3.6.1.5.5.7.6.50"
    "MLDSA87-Ed448-SHAKE256                mldsa87_ed448_shake256                 1.3.6.1.5.5.7.6.51"
    "MLDSA87-RSA3072-PSS-SHA512            mldsa87_rsa3072_pss_sha512             1.3.6.1.5.5.7.6.52"
    "MLDSA87-RSA4096-PSS-SHA512            mldsa87_rsa4096_pss_sha512             1.3.6.1.5.5.7.6.53"
    "MLDSA87-ECDSA-P521-SHA512             mldsa87_ecdsa_p521_sha512              1.3.6.1.5.5.7.6.54"
)

# ─── All 12 composite KEM algorithms ────────────────────────────────────────
# Format per entry:
#   "OPENSSL_GENPKEY_NAME  r5_friendly_prefix  oid  signing_ta_oid"
#
# The signing_ta_oid chooses the ML-DSA TA of the equivalent ML-KEM security
# level, matching the R5 README requirement.  Where the signature OID set has a
# natural matching traditional component, use it.  The RSA2048 KEM has no
# MLDSA65-RSA2048 signature TA in the R5 OID set, so use the MLDSA65-RSA3072
# PSS TA as the level-3 ML-DSA TA.
COMPOSITE_KEM_ALGOS=(
    "id-MLKEM768-RSA2048-SHA3-256                       id-MLKEM768-RSA2048-SHA3-256                       1.3.6.1.5.5.7.6.55  1.3.6.1.5.5.7.6.41"
    "id-MLKEM768-RSA3072-SHA3-256                       id-MLKEM768-RSA3072-SHA3-256                       1.3.6.1.5.5.7.6.56  1.3.6.1.5.5.7.6.41"
    "id-MLKEM768-RSA4096-SHA3-256                       id-MLKEM768-RSA4096-SHA3-256                       1.3.6.1.5.5.7.6.57  1.3.6.1.5.5.7.6.43"
    "id-MLKEM768-X25519-SHA3-256                        id-MLKEM768-X25519-SHA3-256                        1.3.6.1.5.5.7.6.58  1.3.6.1.5.5.7.6.48"
    "id-MLKEM768-ECDH-P256-SHA3-256                     id-MLKEM768-ECDH-P256-SHA3-256                     1.3.6.1.5.5.7.6.59  1.3.6.1.5.5.7.6.45"
    "id-MLKEM768-ECDH-P384-SHA3-256                     id-MLKEM768-ECDH-P384-SHA3-256                     1.3.6.1.5.5.7.6.60  1.3.6.1.5.5.7.6.46"
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256          id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256          1.3.6.1.5.5.7.6.61  1.3.6.1.5.5.7.6.47"
    "id-MLKEM1024-RSA3072-SHA3-256                      id-MLKEM1024-RSA3072-SHA3-256                      1.3.6.1.5.5.7.6.62  1.3.6.1.5.5.7.6.52"
    "id-MLKEM1024-ECDH-P384-SHA3-256                    id-MLKEM1024-ECDH-P384-SHA3-256                    1.3.6.1.5.5.7.6.63  1.3.6.1.5.5.7.6.49"
    "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256         id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256         1.3.6.1.5.5.7.6.64  1.3.6.1.5.5.7.6.50"
    "id-MLKEM1024-X448-SHA3-256                         id-MLKEM1024-X448-SHA3-256                         1.3.6.1.5.5.7.6.65  1.3.6.1.5.5.7.6.51"
    "id-MLKEM1024-ECDH-P521-SHA3-256                    id-MLKEM1024-ECDH-P521-SHA3-256                    1.3.6.1.5.5.7.6.66  1.3.6.1.5.5.7.6.54"
)

# ─── Counters ────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
declare -a FAILURES=()
SIGNING_TA_KEY=""
SIGNING_TA_DER=""

# ─── Temp working dirs ───────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d /tmp/gen_composite_r5.XXXXXX)"
STAGING_DIR="${WORK_DIR}/staging"
mkdir -p "${STAGING_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

extract_pkcs8_private_octets() {
    local der_file="$1"
    local raw_file="$2"
    local hex

    hex="$("${OPENSSL_BIN}" asn1parse -inform DER -in "${der_file}" \
        | awk '/prim: OCTET STRING/ { sub(/^.*\[HEX DUMP\]:/, ""); print; exit }')"
    if [[ -z "${hex}" ]]; then
        return 1
    fi
    printf "%s" "${hex}" | xxd -r -p > "${raw_file}"
}

signing_ta_for_oid() {
    local signer_oid="$1"

    case "${signer_oid}" in
        "1.3.6.1.5.5.7.6.41")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-RSA3072-PSS-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_rsa3072_pss_sha512-1.3.6.1.5.5.7.6.41_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.43")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-RSA4096-PSS-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_rsa4096_pss_sha512-1.3.6.1.5.5.7.6.43_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.45")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-ECDSA-P256-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_ecdsa_p256_sha512-1.3.6.1.5.5.7.6.45_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.46")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-ECDSA-P384-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_ecdsa_p384_sha512-1.3.6.1.5.5.7.6.46_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.47")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-ECDSA-brainpoolP256r1-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_ecdsa_brainpoolp256r1_sha512-1.3.6.1.5.5.7.6.47_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.48")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA65-Ed25519-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa65_ed25519_sha512-1.3.6.1.5.5.7.6.48_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.49")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA87-ECDSA-P384-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa87_ecdsa_p384_sha512-1.3.6.1.5.5.7.6.49_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.50")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA87-ECDSA-brainpoolP384r1-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa87_ecdsa_brainpoolp384r1_sha512-1.3.6.1.5.5.7.6.50_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.51")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA87-Ed448-SHAKE256.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa87_ed448_shake256-1.3.6.1.5.5.7.6.51_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.52")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA87-RSA3072-PSS-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa87_rsa3072_pss_sha512-1.3.6.1.5.5.7.6.52_ta.der"
            ;;
        "1.3.6.1.5.5.7.6.54")
            SIGNING_TA_KEY="${WORK_DIR}/key_MLDSA87-ECDSA-P521-SHA512.pem"
            SIGNING_TA_DER="${STAGING_DIR}/mldsa87_ecdsa_p521_sha512-1.3.6.1.5.5.7.6.54_ta.der"
            ;;
        *)
            return 1
            ;;
    esac

    [[ -f "${SIGNING_TA_KEY}" && -f "${SIGNING_TA_DER}" ]]
}

# ─── Header ──────────────────────────────────────────────────────────────────
echo "Composite Signature and KEM R5 Artifact Generation"
echo "=================================================="
echo "OpenSSL:  ${OPENSSL_BIN}"
echo "Output:   ${OUTPUT_DIR}/artifacts_certs_r5.zip"
echo ""

# ─── Main generation loop ────────────────────────────────────────────────────
for entry in "${COMPOSITE_ALGOS[@]}"; do
    read -r ossl_name friendly oid <<< "${entry}"

    file_base="${friendly}-${oid}"
    ta_file="${STAGING_DIR}/${file_base}_ta.der"
    priv_file="${STAGING_DIR}/${file_base}_priv.der"
    temp_key="${WORK_DIR}/key_${ossl_name}.pem"

    printf "  %-50s " "${ossl_name}"

    # Step 1: Generate composite keypair as PKCS#8 PEM
    if ! keygen_err="$("${OPENSSL_BIN}" genpkey \
            -algorithm "${ossl_name}" \
            -out "${temp_key}" 2>&1)"; then
        echo "FAIL (keygen)"
        echo "${keygen_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: keygen failed")
        continue
    fi

    # Step 2: Self-signed TA certificate in DER format
    # basicConstraints and keyUsage make it a proper CA cert.
    if ! cert_err="$("${OPENSSL_BIN}" req -new -x509 \
            -key "${temp_key}" \
            -days 3650 \
            -subj "/CN=${file_base}" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -outform DER \
            -out "${ta_file}" 2>&1)"; then
        echo "FAIL (cert)"
        echo "${cert_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: certificate generation failed")
        continue
    fi

    # Step 3: Export private key as PKCS#8 DER
    # genpkey outputs PKCS#8 PEM already; strip the PEM headers and base64-
    # decode to get the identical DER.  `openssl pkey -outform DER` silently
    # fails for composite keys in OpenSSL 4.x, so we avoid it here.
    if ! grep -v '^-----' "${temp_key}" | base64 -d > "${priv_file}" 2>&1; then
        echo "FAIL (pkey export)"
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: PKCS#8 DER export failed")
        continue
    fi

    echo "OK"
    PASS=$((PASS + 1))
done

echo ""
echo "Composite KEM artifacts"
echo "-----------------------"

for entry in "${COMPOSITE_KEM_ALGOS[@]}"; do
    read -r ossl_name friendly oid signer_oid <<< "${entry}"

    file_base="${friendly}-${oid}"
    ee_file="${STAGING_DIR}/${file_base}_ee.der"
    priv_file="${STAGING_DIR}/${file_base}_priv.der"
    priv_raw_file="${STAGING_DIR}/${file_base}_priv.raw"
    ct_file="${STAGING_DIR}/${file_base}_ciphertext.bin"
    ss_file="${STAGING_DIR}/${file_base}_ss.bin"
    temp_key="${WORK_DIR}/key_${ossl_name}.pem"
    temp_pub="${WORK_DIR}/pub_${ossl_name}.pem"
    ext_file="${WORK_DIR}/${file_base}.ext"

    printf "  %-50s " "${ossl_name}"

    if ! signing_ta_for_oid "${signer_oid}"; then
        echo "FAIL (signing TA)"
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: required signing TA ${signer_oid} is unavailable")
        continue
    fi

    if ! keygen_err="$("${OPENSSL_BIN}" genpkey \
            -algorithm "${ossl_name}" \
            -out "${temp_key}" 2>&1)"; then
        echo "FAIL (keygen)"
        echo "${keygen_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM keygen failed")
        continue
    fi

    if ! pub_err="$("${OPENSSL_BIN}" pkey \
            -in "${temp_key}" \
            -pubout \
            -out "${temp_pub}" 2>&1)"; then
        echo "FAIL (pubout)"
        echo "${pub_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM public key export failed")
        continue
    fi

    # As with the signature keys, genpkey already wrote unencrypted PKCS#8 PEM.
    if ! grep -v '^-----' "${temp_key}" | base64 -d > "${priv_file}" 2>&1; then
        echo "FAIL (pkey export)"
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM PKCS#8 DER export failed")
        continue
    fi
    if ! extract_pkcs8_private_octets "${priv_file}" "${priv_raw_file}"; then
        echo "FAIL (raw export)"
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM raw private key export failed")
        continue
    fi

    {
        printf "subjectKeyIdentifier=none\n"
        printf "subjectAltName=critical,DNS:%s.ee.example\n" "${friendly}"
        printf "basicConstraints=critical,CA:false\n"
        printf "keyUsage=critical,keyEncipherment\n"
    } > "${ext_file}"

    if ! cert_err="$("${OPENSSL_BIN}" x509 -new \
            -outform DER \
            -out "${ee_file}" \
            -CAform DER \
            -CA "${SIGNING_TA_DER}" \
            -CAkey "${SIGNING_TA_KEY}" \
            -force_pubkey "${temp_pub}" \
            -days 3650 \
            -subj "/" \
            -extfile "${ext_file}" 2>&1)"; then
        echo "FAIL (ee cert)"
        echo "${cert_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM EE certificate generation failed")
        continue
    fi

    if ! encap_err="$("${OPENSSL_BIN}" pkeyutl \
            -encap \
            -inkey "${temp_pub}" \
            -out "${ct_file}" \
            -secret "${ss_file}" 2>&1)"; then
        echo "FAIL (encap)"
        echo "${encap_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: KEM encapsulation failed")
        continue
    fi

    echo "OK"
    PASS=$((PASS + 1))
done

# ─── Pack zip ────────────────────────────────────────────────────────────────
echo ""

mapfile -t artifacts < <(find "${STAGING_DIR}" -maxdepth 1 \
    \( -name "*_ta.der" -o -name "*_ee.der" -o -name "*_priv.der" \
       -o -name "*_priv.raw" -o -name "*_ciphertext.bin" \
       -o -name "*_ss.bin" \) | sort)

ZIP_PATH="${OUTPUT_DIR}/artifacts_certs_r5.zip"
rm -f "${ZIP_PATH}"

if [[ ${#artifacts[@]} -eq 0 ]]; then
    echo "ERROR: no artifacts were generated — zip not created."
    exit 1
fi

if ! zip_err="$(zip -j -q "${ZIP_PATH}" "${artifacts[@]}" 2>&1)"; then
    echo "ERROR: zip failed:"
    echo "${zip_err}" | sed 's/^/  /'
    exit 1
fi

if ! cp "${artifacts[@]}" "${OUTPUT_DIR}/"; then
    echo "ERROR: failed to copy generated artifacts into ${OUTPUT_DIR}"
    exit 1
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo "==========================================="
printf "Generated: %d/%d algorithms\n" "${PASS}" "$((PASS + FAIL))"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "Failed:"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}"
    done
fi

echo ""
echo "Zip:  ${ZIP_PATH}"
echo "Size: $(du -sh "${ZIP_PATH}" | cut -f1)"
echo "Files copied into: ${OUTPUT_DIR}"
echo ""

[[ ${FAIL} -eq 0 ]]
