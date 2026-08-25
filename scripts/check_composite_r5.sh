#!/usr/bin/env bash
# check_composite_r5.sh
#
# Verifies R5 composite signature artifacts for all 18 combinations:
#   1. TA certificate: openssl verify -CAfile <name>_ta.der <name>_ta.der
#   2. Private key: sign test data with _priv.der, verify against _ta.der public key
#
# Verifies R5 composite KEM artifacts for all 12 combinations:
#   1. EE certificate: verify against the expected equivalent-level ML-DSA TA,
#      parse KEM SPKI, and perform an encapsulation
#   2. Consistency: _priv.der public key matches _ee.der public key
#   3. Private key: decapsulate _ciphertext.bin and compare _ss.bin
#
# R5 naming convention (from readme + oid_mapping.md):
#   <friendly>-<oid>_ta.der   (e.g. id-MLDSA44-RSA2048-PSS-SHA256-1.3.6.1.5.5.7.6.37_ta.der)
#   <friendly>-<oid>_priv.der
#   <friendly>-<oid>_ee.der
#   <friendly>-<oid>_ciphertext.bin
#   <friendly>-<oid>_ss.bin
#
# Usage:
#   ./check_composite_r5.sh [artifacts_certs_r5_dir]
#
# Environment variables:
#   OPENSSL_DIR   - OpenSSL source/build directory (default: workspace root)
#   OPENSSL_BIN   - Path to openssl binary (default: OPENSSL_DIR/apps/openssl)
#   OPENSSL_CONF  - Path to openssl.cnf (optional)

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

# ─── Artifacts directory ─────────────────────────────────────────────────────
# The zip extracts into test/artifacts_certs_r5/
ARTIFACTS_DIR="${1:-${WORKSPACE_ROOT}/test/artifacts_certs_r5}"

# ─── All 18 composite signature algorithms ───────────────────────────────────
# Source: oid_mapping.md / draft-ietf-lamps-pq-composite-sigs-12
# Each entry: "friendly_name OID"
COMPOSITE_ALGOS=(
    "id-MLDSA44-RSA2048-PSS-SHA256            1.3.6.1.5.5.7.6.37"
    "id-MLDSA44-RSA2048-PKCS15-SHA256         1.3.6.1.5.5.7.6.38"
    "id-MLDSA44-Ed25519-SHA512                1.3.6.1.5.5.7.6.39"
    "id-MLDSA44-ECDSA-P256-SHA256             1.3.6.1.5.5.7.6.40"
    "id-MLDSA65-RSA3072-PSS-SHA512            1.3.6.1.5.5.7.6.41"
    "id-MLDSA65-RSA3072-PKCS15-SHA512         1.3.6.1.5.5.7.6.42"
    "id-MLDSA65-RSA4096-PSS-SHA512            1.3.6.1.5.5.7.6.43"
    "id-MLDSA65-RSA4096-PKCS15-SHA512         1.3.6.1.5.5.7.6.44"
    "id-MLDSA65-ECDSA-P256-SHA512             1.3.6.1.5.5.7.6.45"
    "id-MLDSA65-ECDSA-P384-SHA512             1.3.6.1.5.5.7.6.46"
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512  1.3.6.1.5.5.7.6.47"
    "id-MLDSA65-Ed25519-SHA512                1.3.6.1.5.5.7.6.48"
    "id-MLDSA87-ECDSA-P384-SHA512             1.3.6.1.5.5.7.6.49"
    "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512  1.3.6.1.5.5.7.6.50"
    "id-MLDSA87-Ed448-SHAKE256                1.3.6.1.5.5.7.6.51"
    "id-MLDSA87-RSA3072-PSS-SHA512            1.3.6.1.5.5.7.6.52"
    "id-MLDSA87-RSA4096-PSS-SHA512            1.3.6.1.5.5.7.6.53"
    "id-MLDSA87-ECDSA-P521-SHA512             1.3.6.1.5.5.7.6.54"
)

# ─── All 12 composite KEM algorithms ────────────────────────────────────────
# Source: docs/oid_mapping.md / draft-ietf-lamps-pq-composite-kem
# Each entry: "friendly_name OID expected_signing_ta_oid"
COMPOSITE_KEM_ALGOS=(
    "id-MLKEM768-RSA2048-SHA3-256                       1.3.6.1.5.5.7.6.55  1.3.6.1.5.5.7.6.41"
    "id-MLKEM768-RSA3072-SHA3-256                       1.3.6.1.5.5.7.6.56  1.3.6.1.5.5.7.6.41"
    "id-MLKEM768-RSA4096-SHA3-256                       1.3.6.1.5.5.7.6.57  1.3.6.1.5.5.7.6.43"
    "id-MLKEM768-X25519-SHA3-256                        1.3.6.1.5.5.7.6.58  1.3.6.1.5.5.7.6.48"
    "id-MLKEM768-ECDH-P256-SHA3-256                     1.3.6.1.5.5.7.6.59  1.3.6.1.5.5.7.6.45"
    "id-MLKEM768-ECDH-P384-SHA3-256                     1.3.6.1.5.5.7.6.60  1.3.6.1.5.5.7.6.46"
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256          1.3.6.1.5.5.7.6.61  1.3.6.1.5.5.7.6.47"
    "id-MLKEM1024-RSA3072-SHA3-256                      1.3.6.1.5.5.7.6.62  1.3.6.1.5.5.7.6.52"
    "id-MLKEM1024-ECDH-P384-SHA3-256                    1.3.6.1.5.5.7.6.63  1.3.6.1.5.5.7.6.49"
    "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256         1.3.6.1.5.5.7.6.64  1.3.6.1.5.5.7.6.50"
    "id-MLKEM1024-X448-SHA3-256                         1.3.6.1.5.5.7.6.65  1.3.6.1.5.5.7.6.51"
    "id-MLKEM1024-ECDH-P521-SHA3-256                    1.3.6.1.5.5.7.6.66  1.3.6.1.5.5.7.6.54"
)

# ─── Counters ────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
declare -a FAILURES=()

# ─── Temp dir, cleaned on exit ───────────────────────────────────────────────
WORK_DIR="$(mktemp -d /tmp/composite_check.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

TEST_DATA="${WORK_DIR}/testdata.bin"
printf 'This is a test of signature data' > "${TEST_DATA}"

# ─── Helper: print padded result ─────────────────────────────────────────────
print_result() {
    local label="$1" name="$2" result="$3" detail="${4:-}"
    printf "  [%-7s] %-68s %s" "${label}" "${name}" "${result}"
    if [[ -n "${detail}" ]]; then
        printf " (%s)" "${detail}"
    fi
    printf "\n"
}

# ─── Verify TA cert (self-signed) ────────────────────────────────────────────
# -check_ss_sig forces OpenSSL to actually verify the signature on the
# self-signed cert rather than short-circuiting it as a trust anchor.
check_ta_cert() {
    local label="$1" ta_file="$2"

    local ta_pem="${WORK_DIR}/ta_$$.pem"
    local err

    # Convert DER to PEM (-CAfile requires PEM)
    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ta_file}" -out "${ta_pem}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "CERT" "${label}" "FAIL" "DER to PEM conversion failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("CERT: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" verify -CAfile "${ta_pem}" -check_ss_sig "${ta_pem}" 2>&1)"
    if [[ $? -eq 0 ]]; then
        print_result "CERT" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "CERT" "${label}" "FAIL"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("CERT: ${label}")
    fi
}

# ─── Verify private key via sign + verify round-trip ─────────────────────────
check_priv_key() {
    local label="$1" ta_file="$2" priv_file="$3"

    local sig_file="${WORK_DIR}/sig_$$.bin"
    local pub_file="${WORK_DIR}/pub_$$.pem"
    local err

    # Extract public key from TA cert
    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ta_file}" \
            -pubkey -noout -out "${pub_file}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "PRIVKEY" "${label}" "FAIL" "pubkey extraction failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
        return
    fi

    # Sign test data with the private key (DER format)
    # Use -rawin so pkeyutl routes through digest_sign_* (required for composite).
    # No -digest flag: composite determines its own hash algorithm internally.
    err="$("${OPENSSL_BIN}" pkeyutl -sign \
            -inkey "${priv_file}" -keyform DER \
            -rawin \
            -in "${TEST_DATA}" \
            -out "${sig_file}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "PRIVKEY" "${label}" "FAIL" "signing failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
        return
    fi

    # Verify signature against the TA public key
    err="$("${OPENSSL_BIN}" pkeyutl -verify \
            -pubin -inkey "${pub_file}" \
            -rawin \
            -in "${TEST_DATA}" \
            -sigfile "${sig_file}" 2>&1)"
    if [[ $? -eq 0 ]]; then
        print_result "PRIVKEY" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "PRIVKEY" "${label}" "FAIL" "signature verification failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
    fi
}

# ─── Verify KEM EE cert and KEM public key usability ─────────────────────────
check_kem_ee_cert() {
    local label="$1" ee_file="$2" expected_signer_oid="$3"

    local ee_pem="${WORK_DIR}/ee_$$.pem"
    local ee_pub="${WORK_DIR}/ee_pub_$$.pem"
    local ct_file="${WORK_DIR}/ee_ct_$$.bin"
    local ss_file="${WORK_DIR}/ee_ss_$$.bin"
    local ta_file ta_pem err

    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ee_file}" \
            -out "${ee_pem}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCERT" "${label}" "FAIL" "DER to PEM conversion failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ee_file}" \
            -pubkey -noout -out "${ee_pub}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCERT" "${label}" "FAIL" "pubkey extraction failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
        return
    fi

    ta_file="$(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${expected_signer_oid}_ta.der" 2>/dev/null | sort | head -n 1)"
    if [[ -z "${ta_file}" ]]; then
        print_result "KEMCERT" "${label}" "FAIL" "expected TA ${expected_signer_oid} not found"
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
        return
    fi

    ta_pem="${WORK_DIR}/ta_for_ee_$(basename "${ta_file}").pem"
    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ta_file}" -out "${ta_pem}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCERT" "${label}" "FAIL" "expected TA DER to PEM conversion failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" verify -CAfile "${ta_pem}" "${ee_pem}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCERT" "${label}" "FAIL" "EE not signed by expected TA ${expected_signer_oid}"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" pkeyutl -encap \
            -inkey "${ee_pub}" \
            -out "${ct_file}" \
            -secret "${ss_file}" 2>&1)"
    if [[ $? -eq 0 ]]; then
        print_result "KEMCERT" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "KEMCERT" "${label}" "FAIL" "encapsulation failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCERT: ${label}")
    fi
}

# ─── Verify KEM private key/public cert consistency ──────────────────────────
check_kem_consistency() {
    local label="$1" ee_file="$2" priv_file="$3"

    local ee_pub="${WORK_DIR}/ee_consistency_pub_$$.pem"
    local priv_pub="${WORK_DIR}/priv_consistency_pub_$$.pem"
    local err

    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ee_file}" \
            -pubkey -noout -out "${ee_pub}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCONS" "${label}" "FAIL" "EE pubkey extraction failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCONS: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" pkey -inform DER -in "${priv_file}" \
            -pubout -out "${priv_pub}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMCONS" "${label}" "FAIL" "private pubout failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCONS: ${label}")
        return
    fi

    if cmp -s "${ee_pub}" "${priv_pub}"; then
        print_result "KEMCONS" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "KEMCONS" "${label}" "FAIL" "public keys differ"
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMCONS: ${label}")
    fi
}

# ─── Verify KEM private key via decapsulation ────────────────────────────────
check_kem_priv_key() {
    local label="$1" priv_file="$2" ct_file="$3" ss_file="$4"

    local actual_ss="${WORK_DIR}/actual_ss_$$.bin"
    local err

    err="$("${OPENSSL_BIN}" pkeyutl -decap \
            -inkey "${priv_file}" -keyform DER \
            -in "${ct_file}" \
            -secret "${actual_ss}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "KEMPRIV" "${label}" "FAIL" "decapsulation failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMPRIV: ${label}")
        return
    fi

    if cmp -s "${actual_ss}" "${ss_file}"; then
        print_result "KEMPRIV" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "KEMPRIV" "${label}" "FAIL" "shared secret mismatch"
        FAIL=$((FAIL + 1))
        FAILURES+=("KEMPRIV: ${label}")
    fi
}

# ─── Header ──────────────────────────────────────────────────────────────────
echo "Composite Signature and KEM R5 Artifact Verification"
echo "===================================================="
echo "OpenSSL:    ${OPENSSL_BIN}"
echo "Artifacts:  ${ARTIFACTS_DIR}"
echo ""

if [[ ! -d "${ARTIFACTS_DIR}" ]]; then
    echo "ERROR: artifacts directory not found: ${ARTIFACTS_DIR}"
    echo "       Extract artifacts_certs_r5.zip into test/ at the workspace root."
    exit 1
fi

# ─── Main loop ───────────────────────────────────────────────────────────────
for entry in "${COMPOSITE_ALGOS[@]}"; do
    friendly="${entry%% *}"
    oid="${entry##* }"

    echo "${friendly} (${oid}):"

    # Locate files by OID only — the friendly-name prefix may vary per provider
    mapfile -t ta_matches  < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_ta.der"   2>/dev/null | sort)
    mapfile -t priv_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_priv.der" 2>/dev/null | sort)

    ta_file="${ta_matches[0]:-}"
    priv_file="${priv_matches[0]:-}"

    # Use the actual filename (minus directory) as the display label
    ta_label="${ta_file:+$(basename "${ta_file}" _ta.der)}"
    priv_label="${priv_file:+$(basename "${priv_file}" _priv.der)}"

    # --- TA cert verification ---
    if [[ -z "${ta_file}" ]]; then
        print_result "CERT" "${oid}" "SKIP" "no *${oid}_ta.der found"
        SKIP=$((SKIP + 1))
    else
        check_ta_cert "${ta_label}" "${ta_file}"
    fi

    # --- Private key round-trip test ---
    if [[ -z "${priv_file}" ]]; then
        print_result "PRIVKEY" "${oid}" "SKIP" "no *${oid}_priv.der found"
        SKIP=$((SKIP + 1))
    elif [[ -z "${ta_file}" ]]; then
        print_result "PRIVKEY" "${oid}" "SKIP" "TA not found, cannot extract public key"
        SKIP=$((SKIP + 1))
    else
        check_priv_key "${priv_label}" "${ta_file}" "${priv_file}"
    fi
done

# ─── KEM loop ────────────────────────────────────────────────────────────────
for entry in "${COMPOSITE_KEM_ALGOS[@]}"; do
    read -r friendly oid expected_signer_oid <<< "${entry}"

    echo "${friendly} (${oid}):"

    mapfile -t ee_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_ee.der" 2>/dev/null | sort)
    mapfile -t priv_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_priv.der" 2>/dev/null | sort)
    mapfile -t ct_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_ciphertext.bin" 2>/dev/null | sort)
    mapfile -t ss_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_ss.bin" 2>/dev/null | sort)

    ee_file="${ee_matches[0]:-}"
    priv_file="${priv_matches[0]:-}"
    ct_file="${ct_matches[0]:-}"
    ss_file="${ss_matches[0]:-}"

    ee_label="${ee_file:+$(basename "${ee_file}" _ee.der)}"
    priv_label="${priv_file:+$(basename "${priv_file}" _priv.der)}"

    if [[ -z "${ee_file}" ]]; then
        print_result "KEMCERT" "${oid}" "SKIP" "no *${oid}_ee.der found"
        SKIP=$((SKIP + 1))
    else
        check_kem_ee_cert "${ee_label}" "${ee_file}" "${expected_signer_oid}"
    fi

    if [[ -z "${ee_file}" || -z "${priv_file}" ]]; then
        print_result "KEMCONS" "${oid}" "SKIP" "missing EE cert or private key"
        SKIP=$((SKIP + 1))
    else
        check_kem_consistency "${priv_label}" "${ee_file}" "${priv_file}"
    fi

    if [[ -z "${priv_file}" || -z "${ct_file}" || -z "${ss_file}" ]]; then
        print_result "KEMPRIV" "${oid}" "SKIP" "missing private key, ciphertext, or shared secret"
        SKIP=$((SKIP + 1))
    else
        check_kem_priv_key "${priv_label}" "${priv_file}" "${ct_file}" "${ss_file}"
    fi
done

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
printf "Results: %d passed, %d failed, %d skipped\n" "${PASS}" "${FAIL}" "${SKIP}"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "Failed checks:"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}"
    done
fi

echo ""
[[ ${FAIL} -eq 0 ]]
