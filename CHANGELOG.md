# Revision history for boringssl

## 0.1.0.0

* Initial release with bindings to BoringSSL's cryptographic primitives:
  * Hash functions: SHA-1, SHA-2 family, MD5, BLAKE2b-256 (one-shot and streaming)
  * HMAC, HKDF (RFC 5869), PBKDF2 (RFC 6070), Scrypt (RFC 7914)
  * AEAD: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV, and more
  * Symmetric ciphers: AES in CBC, CTR, ECB, OFB modes
  * Ed25519 (RFC 8032), X25519 (RFC 7748)
  * ECDSA and ECDH over P-256, P-384, P-521
  * RSA: PKCS#1 v1.5, PSS signing, OAEP encryption
  * Post-quantum: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA, X-Wing
  * HPKE (RFC 9180), SPAKE2, TrustToken
  * Base64, PEM encoding/decoding, X.509 certificate parsing
  * CMAC, SipHash, TLS PRF

* The public API follows the conventions specified in `CONVENTIONS.md`:

  * __Three-tier failure model.__ Deterministic and total operations return
    bare values (`hash`, `hmac`); deterministic but fallible operations
    return pure `Either CryptoError` (KDFs, parsing, AEAD `seal`/`open`,
    deterministic signing); operations that consume randomness or mutate a
    context are in `IO` (key generation, randomized signing, streaming
    contexts, HPKE). No public function calls `error` or `fail`, and none
    silently substitutes a default on bad input.
  * __Verification returns fail-closed `Bool`.__ Signature and MAC
    verification cannot be misread: there is no `Right False` to mistake
    for success.
  * __Authenticated decryption failure is distinct.__ AEAD `open` and HPKE
    `recipientOpen` report tampering as `AuthenticationFailed`, separate
    from caller errors. ML-KEM and X-Wing document FIPS 203 implicit
    rejection, where a tampered ciphertext yields a different secret rather
    than an error.
  * __Typed keys.__ Every algorithm's keys and fixed-format signatures are
    opaque newtypes with validating smart constructors; private keys are
    `SecureBytes`-backed with redacted `Show` and constant-time `Eq`. RSA
    enforces its 2048-bit minimum on import as well as generation.
  * __Hardened `SecureBytes`.__ Page-aligned allocation outside the GC
    heap, best-effort `mlock`/`VirtualLock`, core-dump exclusion, and
    `OPENSSL_cleanse` on release. `Crypto.BoringSSL.Random.randomSecureBytes`
    generates keys directly into it, and HKDF's `PRK` keeps the intermediate
    secret from round-tripping through `ByteString`.
  * __Uniform naming and argument order.__ Algorithm-first, output length
    last, `verify pub msg sig`; upper-case acronym constructors
    (`AES256GCM`, `HKDF_SHA256`) across every module.
  * __One error type, one secret type.__ `Crypto.BoringSSL.Error` and
    `Crypto.BoringSSL.SecureBytes` are canonical; `Crypto.BoringSSL` is a
    Haddock guide mapping tasks to modules.
  * Parameter clusters are records (`PBKDF2Params`, `ScryptParams` with
    `defaultScryptParams`) so numeric arguments cannot be transposed.
