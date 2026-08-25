# scripts

Helper scripts for building, testing, and interoperability verification of the
composite provider.

---

## build_and_test.sh

Clones and builds OpenSSL from source if it is not already present, builds the
composite provider, and then delegates to `run_tests.sh` for the full test suite.

**Usage**

```bash
./scripts/build_and_test.sh          # build everything, then run tests
./scripts/build_and_test.sh -f       # soft-clean: remove _build/ before rebuilding
./scripts/build_and_test.sh -F       # hard-clean: remove _build/ and openssl/ before rebuilding
```

**Environment variables**

| Variable         | Default    | Description                                              |
|------------------|------------|----------------------------------------------------------|
| `OPENSSL_BRANCH` | `master`   | Branch or tag to clone from `github.com/openssl/openssl` |
| `MAKE_PARAMS`    | _(empty)_  | Extra flags for every `make` call, e.g. `-j$(nproc)`    |
| `CMAKE_PARAMS`   | _(empty)_  | Extra flags for `cmake`                                  |
| `OSSL_CONFIG`    | _(empty)_  | Extra flags passed to OpenSSL's `./config`               |

**Prerequisites:** `git`, `cmake`, `make`, a C compiler, and `zip`.

---

## run_tests.sh

Runs the compiled unit-test binaries for the composite provider.  Can be invoked
on its own once the provider has been built, or is called automatically by
`build_and_test.sh`.

**Usage**

```bash
# Run all tests (defaults: openssl/ and _build/ under the project root)
./scripts/run_tests.sh

# Run a specific subset
TESTS="test_sign_verify test_oid_registration" ./scripts/run_tests.sh

# Point at a custom build or library location
BUILD_DIR=/tmp/my_build OSSL_LIB_DIR=/opt/openssl/lib ./scripts/run_tests.sh
```

**Environment variables**

| Variable      | Default              | Description                              |
|---------------|----------------------|------------------------------------------|
| `OSSL_LIB_DIR`| `<root>/openssl`     | Directory containing `libcrypto.so*`     |
| `BUILD_DIR`   | `<root>/_build`      | Provider build directory (contains `composite.so` and `tests/`) |
| `TESTS`       | _(all tests)_        | Space-separated list of test binary names to run |

**Tests run** (in order):

| Binary                 | What it covers                                                  |
|------------------------|-----------------------------------------------------------------|
| `test_provider`        | Provider load, name/version params, KEM algorithm availability  |
| `test_encoding`        | Public/private key encode–decode round-trips, KEM wire format   |
| `test_keygen_sig`      | `composite_signkey_generate` for all 18 algorithms              |
| `test_evp_keygen`      | Same via `COMPOSITE_PROVIDER_CTX_new` helper                    |
| `test_sign_verify`     | Sign+verify round-trips, M' context string, tamper detection    |
| `test_oid_registration`| OID registration, `OBJ_find_sigid_algs`, idempotency            |

---

## gen_composite_r5.sh

Generates an `artifacts_certs_r5.zip` containing self-signed TA certificates
and PKCS#8 private keys for all 18 composite signature algorithms, plus EE
certificates, private keys, ciphertexts and shared secrets for all 12 composite
KEM algorithms. The output follows the
[IETF Hackathon pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates) R5 artifact naming convention:

```
<friendly>-<oid>_ta.der    (DER self-signed CA certificate, 10-year)
<friendly>-<oid>_priv.der  (DER PKCS#8 private key)
<friendly>-<oid>_ee.der    (DER EE certificate carrying a KEM public key)
<friendly>-<oid>_priv.raw  (raw draft KEM private key material)
<friendly>-<oid>_ciphertext.bin
<friendly>-<oid>_ss.bin
```

KEM EE certificates are signed by the ML-DSA TA at the equivalent ML-KEM
security level. ML-KEM-768 combinations chain to ML-DSA-65 TAs; ML-KEM-1024
combinations chain to ML-DSA-87 TAs. Where the R5 composite signature OID set
has a natural matching traditional component, that matching TA is used.

**Usage**

```bash
./scripts/gen_composite_r5.sh               # writes zip and artifacts to scripts/
./scripts/gen_composite_r5.sh /output/dir   # writes zip and artifacts to the given directory
```

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |

**Prerequisites:** The composite provider must already be built (`_build/composite.so`
must exist) and `xxd` must be available for `_priv.raw` extraction. Run
`build_and_test.sh` first.

---

## gen_composite_cms_v3.sh

Generates an `artifacts_cms_v3.zip` containing CMS KEMRecipientInfo artifacts
for all 12 composite KEM algorithms. The generator uses the README's MTI KDF
for the composite KEM OIDs:

```
id-alg-hkdf-with-sha256
```

For each KEM OID it emits:

```
artifacts_cms_v3/<friendly>-<oid>_ee.der
artifacts_cms_v3/<friendly>-<oid>_priv.der
artifacts_cms_v3/<friendly>-<oid>_kemri_id-alg-hkdf-with-sha256.der
artifacts_cms_v3/<friendly>-<oid>_kemri_id-alg-hkdf-with-sha256_ukm.der
artifacts_cms_v3/<friendly>-<oid>_kemri_ukm.der
artifacts_cms_v3/<friendly>-<oid>_kemri_auth_id-alg-hkdf-with-sha256.der
artifacts_cms_v3/<friendly>-<oid>_kemri_auth_id-alg-hkdf-with-sha256_ukm.der
artifacts_cms_v3/<friendly>-<oid>_kemri_auth.der
```

The script expects `gen_composite_r5.sh` to have already generated the matching
`_ee.der` and `_priv.der` files in the provider directory. It reuses the KEM
private keys, but reissues CMS-specific KEM EE certificates under the bundled
ML-DSA-44 TA in `artifacts_cms_v3/ta.der`, matching the CMS v3 artifact shape.

**Usage**

```bash
./scripts/gen_composite_cms_v3.sh /path/to/provider/artifact/dir
```

---

## check_composite_r5.sh

Verifies an `artifacts_certs_r5/` directory of R5 artifacts against the
composite provider. Two checks are performed per signature algorithm and three
checks are performed per KEM algorithm:

- **CERT** — self-signed TA certificate is correctly verified with `-check_ss_sig`.
- **PRIVKEY** — sign test data with the private key and verify the signature
  against the public key extracted from the TA cert.
- **KEMCERT** — EE certificate is chain-verified against the expected
  equivalent-level ML-DSA TA, its KEM public key is extracted, and encapsulation
  succeeds.
- **KEMCONS** — public key derived from `_priv.der` matches the public key in
  `_ee.der`.
- **KEMPRIV** — decapsulating `_ciphertext.bin` with `_priv.der` reproduces
  `_ss.bin`.

**Usage**

```bash
./scripts/check_composite_r5.sh                        # looks in <root>/test/artifacts_certs_r5/
./scripts/check_composite_r5.sh /path/to/artifacts_dir
```

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |
| `OPENSSL_MODULES` | `<root>/_build`             | Directory containing `composite.so` |

**Prerequisites:** The composite provider must already be built.  The artifacts
directory must contain files named `*<oid>_ta.der` and `*<oid>_priv.der`.

---

## test_all_providers.sh

Iterates over every provider directory found under `scripts/providers/`, extracts
its `artifacts_certs_r5.zip`, runs `check_composite_r5.sh` against the composite
provider, generates per-provider CSV compatibility matrices for signature and
KEM artifacts, and writes a full report to `scripts/output.txt`.

**Usage**

```bash
./scripts/test_all_providers.sh             # verify all providers, no CSV output
./scripts/test_all_providers.sh --compat    # also generate compatibility matrix CSVs
```

**Required preparation**

1. Clone the IETF Hackathon PQC Certificates repository:

   ```bash
   git clone https://github.com/IETF-Hackathon/pqc-certificates.git
   ```

2. Copy (or symlink) the provider subdirectories from that repo into
   `scripts/providers/`.  Each provider must contain an `artifacts_certs_r5.zip`:

   ```
   scripts/
   └── providers/
       ├── provider_name1/
       │   └── artifacts_certs_r5.zip
       ├── provider_name2/
       │   └── artifacts_certs_r5.zip
       └── ...
   ```

   The expected layout mirrors `pqc-certificates/providers/<name>/artifacts_certs_r5.zip`.

3. The composite provider must already be built (`_build/composite.so`).

**Output**

- `scripts/output.txt` — full per-provider verification log (always written).
- `scripts/compatMatrices/artifacts_certs_r5/<provider>_composite-crypto.csv` —
  compatibility matrix CSV per provider (`Y`/`N` per OID × {cert, priv}).
  Only generated when `-compat` is passed.

  This format follows the convention used by the
  [IETF Hackathon pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
  repository, where each participating implementation submits a compatibility matrix
  to record cross-provider interoperability results.  A `Y` indicates that the
  composite provider successfully verified the artifact generated by the other
  provider; `N` indicates a failure.

**Environment variables**

| Variable       | Default                        | Description                         |
|----------------|--------------------------------|-------------------------------------|
| `OPENSSL_DIR`  | `<root>/openssl`               | OpenSSL build directory             |
| `OPENSSL_BIN`  | `$OPENSSL_DIR/apps/openssl`    | Path to the `openssl` binary        |
| `OPENSSL_CONF` | `<root>/tests/composite.cnf`   | OpenSSL config that loads the composite provider |
| `OPENSSL_MODULES` | `<root>/_build`             | Directory containing `composite.so` |
