# Composite KEM test vectors

The KAT in `tests/test_kem_decaps_vectors.c` runs against the LAMPS working
group's published vectors. They are **not** vendored in this repository yet —
fetch them before building if you want the KAT to run:

```sh
curl -fsSL \
  https://raw.githubusercontent.com/lamps-wg/draft-composite-kem/main/src/testvectors.json \
  -o tests/data/composite_kem_testvectors.json
```

Then re-run `cmake` so it picks the file up. Without it, `cmake` skips
generating the vector header and the test reports as skipped (exit 77) rather
than passing vacuously.

Vendored copy provenance:

- draft version: `draft-ietf-lamps-pq-composite-kem-18` (repo `main` branch)
- retrieved: 2026-08-07
- source commit: `lamps-wg/draft-composite-kem@d77e75420034d826e14cbef0b779986511f114e9`

## Name mismatch to check first

`tests/tools/gen_kem_vectors.py` expects each test case's `tcId` to be the
short name this provider registers, e.g. `id-MLKEM768-RSA2048-SHA3-256`. The
draft has at times labelled the RSA and ECDH combinations `-HMAC-SHA256` /
`-HMAC-SHA512` instead. If the names disagree the script stops and prints the
`tcId` values it actually found.

Do not simply rename to make it pass. Which of the two is correct determines
which KDF the combiner should be using, so a mismatch is a question about
`composite_kem_combine_shared_secret()` and the labels in
`composite_kem_info.c`, not about the test harness.
