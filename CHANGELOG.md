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
