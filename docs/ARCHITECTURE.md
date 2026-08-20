# Architecture

This document describes the internal architecture of the Composite Provider.

## Overview

The Composite Provider is an OpenSSL 3.0+ provider that implements composite post-quantum cryptographic algorithms. It combines ML-DSA (Module-Lattice-Based Digital Signature Algorithm) and ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) with traditional algorithms.

## Directory Structure

```
composite-src/
├── include/              # Public header files
│   └── composite_provider.h
├── src/             # Provider implementation
│   ├── common/           # Provider entrypoint and shared infrastructure
│   ├── kem/              # Composite ML-KEM implementation
│   └── signature/        # Composite ML-DSA signature implementation
│   ├── provider.c        # Provider initialization and registration
│   ├── composite_sig.c   # Signature operations implementation
│   ├── composite_kem.c   # KEM operations implementation
│   ├── mldsa_composite.c # ML-DSA algorithm dispatch
│   └── mlkem_composite.c # ML-KEM algorithm dispatch
├── tests/                # Test suite
│   └── test_provider.c
└── examples/             # Usage examples
    └── load_provider.c
```

## Components

### Provider Core (`provider.c`)

The provider core implements:
- `OSSL_provider_init()`: Entry point called by OpenSSL
- Provider context management
- Parameter queries (name, version, status)
- Operation dispatch

### Algorithm Implementations

#### Signature Operations (`composite_sig.c`)

Implements the OpenSSL signature interface:
- Context creation/destruction
- Sign initialization
- Sign operation
- Verify initialization
- Verify operation
- Digest sign/verify variants

#### KEM Operations (`composite_kem.c`)

Implements the OpenSSL KEM interface:
- Context creation/destruction
- Encapsulate initialization
- Encapsulate operation
- Decapsulate initialization
- Decapsulate operation

### Algorithm Dispatch

#### ML-DSA Dispatch (`mldsa_composite.c`)

Registers 6 composite signature algorithms:
- ML-DSA-44 variants (RSA2048, ECDSA-P256)
- ML-DSA-65 variants (RSA3072, ECDSA-P384)
- ML-DSA-87 variants (RSA4096, ECDSA-P521)

#### ML-KEM Dispatch (`mlkem_composite.c`)

Registers the 12 composite KEM algorithms of
draft-ietf-lamps-pq-composite-kem-18:
- ML-KEM-768 variants (RSA2048, RSA3072, RSA4096, X25519, ECDH-P256,
  ECDH-P384, ECDH-brainpoolP256r1)
- ML-KEM-1024 variants (RSA3072, ECDH-P384, ECDH-brainpoolP384r1, X448,
  ECDH-P521)

#### KEM Key Encoding (`composite_kem_decoder.c` / `composite_kem_encoder.c`)

PKCS#8 (PrivateKeyInfo) and SubjectPublicKeyInfo codecs for all 12 composite
KEMs, in both PEM and DER. AlgorithmIdentifier parameters are required to be
absent on decode (draft §5.2/§5.3), and the public key is always re-derived
from private material rather than trusted from the encoding.

## Data Flow

### Provider Loading

```
Application
    ↓
OpenSSL Core
    ↓
OSSL_provider_init()
    ↓
Create provider context
    ↓
Register dispatch table
    ↓
Provider active
```

### Signature Operation

```
Application calls EVP_DigestSign*
    ↓
OpenSSL dispatches to provider
    ↓
composite_sig_sign_init()
    ↓
composite_sig_sign()
    ↓
Return composite signature
```

### KEM Operation

```
Application calls EVP_PKEY_encapsulate*
    ↓
OpenSSL dispatches to provider
    ↓
composite_kem_encapsulate_init()
    ↓
composite_kem_encapsulate()
    ↓
Return ciphertext and shared secret
```

Decapsulation mirrors this through `EVP_PKEY_decapsulate*`:
`composite_kem_decapsulate()` splits the ciphertext into its ML-KEM and
traditional halves, decapsulates each component, and feeds both secrets —
together with the traditional ciphertext and the recipient's traditional
public key (recovered from the private key, draft §10.4) — through the
SHA3-256 combiner. Malformed input is reported as an error before the
combiner runs (§3.3).

## Algorithm Structure

### Composite Signature Format

```
CompositeSignature ::= SEQUENCE {
    traditionalSignature  OCTET STRING,
    pqSignature          OCTET STRING
}
```

### Composite KEM Format

```
CompositeCiphertext ::= SEQUENCE {
    traditionalCiphertext  OCTET STRING,
    pqCiphertext          OCTET STRING
}

CompositeSharedSecret ::= OCTET STRING
```

The shared secret is derived by combining:
1. Traditional shared secret (from ECDH)
2. PQ shared secret (from ML-KEM)

## Security Properties

### Signature Security

A composite signature is valid if and only if:
- The ML-DSA signature is valid, AND
- The traditional signature (RSA/ECDSA) is valid

This provides security even if one component is compromised.

### KEM Security

The composite KEM provides:
- IND-CCA2 security
- Security against quantum adversaries (via ML-KEM)
- Security against classical adversaries (via ECDH)

The combined shared secret maintains security if at least one component is secure.

## Extension Points

The architecture supports:
- Adding new composite algorithm combinations
- Implementing key management operations
- Adding parameter customization
- Supporting additional encodings

## Performance Considerations

- Signature operations combine two signatures (sequential)
- KEM operations combine two encapsulations (sequential)
- Memory usage scales with sum of component sizes
- Processing time is sum of component times
