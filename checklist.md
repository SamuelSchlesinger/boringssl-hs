# Test Module Review Checklist

Review each module for completeness and testing strategy.
Goal: make this as robustly tested as possible.

## Public API Modules

- [x] **Digest** (`test/Test/Digest.hs`) — ~49 tests
  - SHA-256, SHA-512, SHA-1, SHA-224, SHA-384, SHA-512/256, MD5, BLAKE2b-256
  - Streaming mode for all 8 algorithms (single/multiple updates, empty updates)
  - `digestSize` constants validation
  - Output length matches `digestSize` for all algorithms
  - `hash` dispatcher equivalence for all 8 algorithms
  - Large input (1MB one-shot and chunked streaming)

- [x] **AEAD** (`test/Test/AEAD.hs`) — ~57 tests
  - All 14 algorithms tested (AES-128/192/256-GCM, ChaCha20/XChaCha20-Poly1305, AES-128/256-GCM-SIV, AES-128/256-CTR-HMAC-SHA256, AES-128/256-EAX, AES-128-CCM-Bluetooth/Bluetooth8/Matter)
  - Round-trip, authentication failure, parameter queries, KATs (RFC 7539, NIST SP 800-38D)
  - Empty plaintext, wrong key length, AD tampering, ciphertext length assertions

- [x] **HMAC** (`test/Test/HMAC.hs`) — ~36 tests
  - RFC 4231 test vectors (SHA-256 x3, SHA-512, SHA-384, SHA-1)
  - Streaming for SHA-256 (single/multi/empty update), SHA-512, SHA-384
  - `hmacVerify` positive/negative, `constTimeEq` edge cases
  - Output length for all 8 algorithms, empty key/message edge cases

- [x] **HKDF** (`test/Test/HKDF.hs`) — ~15 tests
  - RFC 5869 test vectors (SHA-256 x3, SHA-1 x2)
  - Extract, expand, and full HKDF separately tested
  - Extract output length = digestSize for SHA-256/512/1
  - SHA-512 full round-trip and extract+expand consistency
  - Error: expand rejects output > 255*hashLen

- [x] **Random** (`test/Test/Random.hs`) — ~6 tests
  - Correct output length (32, 0, 1024 bytes)
  - Two calls produce different output
  - Negative input returns empty, entropy sanity check

- [x] **Cipher** (`test/Test/Cipher.hs`) — ~40 tests
  - All 8 algorithms (AES-128/256 x CBC/CTR/ECB/OFB)
  - NIST SP 800-38A test vectors, bad padding detection
  - Key/IV length validation, ECB empty IV, stream cipher length assertions
  - Empty plaintext, different IV produces different ciphertext
  - Properties for all 8 algorithms (key/IV/block sizes)

- [x] **Ed25519** (`test/Test/Ed25519.hs`) — ~24 tests
  - Sign/verify round-trip, invalid signature rejection, wrong message
  - RFC 8032 Section 7.1 test vector (with NO_ASM handling)
  - Smart constructors, serialization round-trip
  - keyPairFromSeed wrong length, generateKeyPair uniqueness
  - sign determinism, key/signature size assertions

- [x] **X25519** (`test/Test/X25519.hs`) — ~15 tests
  - Shared secret symmetry, `publicFromPrivate`, RFC 7748 Section 6.1
  - Smart constructors, serialization round-trip
  - Key pair uniqueness, key/secret sizes, `publicFromPrivate` determinism

- [x] **ECDSA** (`test/Test/ECDSA.hs`) — ~22 tests
  - P-256, P-384, P-521 sign/verify round-trip (DER and P1363)
  - Invalid signature rejection for all curves
  - P1363 signature size assertions (64, 96, 132 bytes)
  - Key serialization round-trip for all curves

- [x] **ECDH** (`test/Test/ECDH.hs`) — ~14 tests
  - Key agreement symmetry (P-256, P-384, P-521)
  - Key serialization round-trip, invalid output length rejection
  - Output length assertions, different peers produce different secrets

- [x] **RSA** (`test/Test/RSA.hs`) — ~22 tests
  - 2048-bit keygen, PKCS#1 v1.5, PSS (with wrong-digest rejection), OAEP
  - Max plaintext and too-long-plaintext error, signature size assertions
  - Rejects keys below 2048-bit
  - Serialization round-trip, garbage rejection for pub/priv deserialization

- [x] **Base64** (`test/Test/Base64.hs`) — ~22 tests
  - RFC 4648 encode and decode test vectors
  - Round-trip (empty, text, binary data)
  - Invalid input: bad chars, truncated padding, single char

- [x] **PBKDF2** (`test/Test/PBKDF2.hs`) — ~12 tests
  - RFC 6070 test vectors (HMAC-SHA1)
  - PBKDF2-HMAC-SHA256 round-trip, determinism
  - Different passwords/salts differ, output length

- [x] **ML-KEM** (`test/Test/MLKEM.hs`) — ~19 tests
  - ML-KEM-768 and ML-KEM-1024 keygen, encap/decap, encapsulatePublic
  - Wrong ciphertext rejection for both variants, wrong-length public key
  - Key pair uniqueness, constants validation

- [x] **ML-DSA** (`test/Test/MLDSA.hs`) — ~37 tests
  - MLDSA44, MLDSA65, MLDSA87: 10 tests each (keygen, sign/verify, context, tamper, wrong msg/ctx, key uniqueness, publicKeyFromBytes/Private round-trip)
  - Constants validation (7 tests)

- [x] **X.509** (`test/Test/X509.hs`) — ~7 tests
  - `parseDER` error handling (garbage, empty, truncated)
  - `toDER` round-trip, subject/issuer name parsing
  - Self-signed cert: issuer equals subject

- [x] **PEM** (`test/Test/PEM.hs`) — ~8 tests
  - Encode/decode round-trip, empty data, RSA PRIVATE KEY label
  - Error handling (garbage, missing footer)
  - Header/footer format, line wrapping at 64 characters

- [x] **HPKE** (`test/Test/HPKE.hs`) — ~25 tests
  - KEM: X25519, P-256, MLKEM768, XWing, MLKEM1024
  - AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
  - Round-trip seal/open, multi seal/open, export secret agreement
  - Auth mode (X25519, P-256), auth wrong sender key, wrong key failure

- [x] **SPAKE2** (`test/Test/SPAKE2.hs`) — ~6 tests
  - Alice/Bob agreement, different passwords, empty names, invalid message
  - Key size (64 bytes) and message size (32 bytes) assertions

- [x] **TrustToken** (`test/Test/TrustToken.hs`) — ~5 tests
  - ExperimentV2VOPRF, ExperimentV2PMB, PstV1VOPRF, PstV1PMB full round-trip
  - Batch issuance

- [x] **CMAC** (`test/Test/CMAC.hs`) — ~14 tests
  - AES-128/256 one-shot, RFC 4493 test vectors (3 vectors)
  - Incremental mode (single/multiple updates, AES-256)
  - Input validation: rejects invalid key lengths

- [x] **SLH-DSA** (`test/Test/SLHDSA.hs`) — ~14 tests
  - SHA2_128S: keygen, sign/verify, context, tamper, wrong msg/ctx/key length
  - Constants for both SHA2_128S and SHAKE_256F (6 tests)
  - Note: SHAKE_256F skipped in CI (slow)

- [x] **X-Wing** (`test/Test/XWing.hs`) — ~8 tests
  - Keygen, publicFromPrivate, encapsulate/decapsulate round-trip
  - Size assertions, different encapsulations differ, wrong key, input validation

- [x] **Scrypt** (`test/Test/Scrypt.hs`) — ~7 tests
  - Basic derivation, determinism, different passwords/salts
  - Invalid N rejection, output length assertion

- [x] **SipHash** (`test/Test/SipHash.hs`) — ~5 tests
  - Determinism, different keys/inputs, empty input
  - SipHash-2-4 reference test vector

- [x] **TLS PRF** (`test/Test/TLSPRF.hs`) — ~7 tests
  - Output length, determinism, SHA-384 support
  - Different secrets/labels/algorithms, empty seed2

## Cross-Cutting

- [x] **Properties** (`test/Test/Properties.hs`) — ~50+ property tests
  - QuickCheck properties across Digest, AEAD (all 14 algorithms), HMAC, HKDF, Cipher (all 8 algorithms), Ed25519, X25519, ECDSA, ECDH, RSA, Base64, Random

## Internal Modules (tested indirectly)

- [x] **Internal.Error** — tested via all modules returning `CryptoError`
- [x] **Internal.Buffer** — tested via all FFI-wrapping modules
- [x] **Internal.Digest** — tested via Digest, HMAC, HKDF, PBKDF2
- [x] **Internal.ECKey** — tested via ECDSA, ECDH
- [x] **Internal.FFI** — tested indirectly through all 26 public API modules
