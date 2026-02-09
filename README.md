# boringssl

Idiomatic Haskell bindings to Google's [BoringSSL](https://boringssl.googlesource.com/boringssl/) cryptography library.

> **Warning:** This library is experimental and under active construction. The API
> is unstable and may change without notice. Do not use this in production systems.

## Overview

This library provides idiomatic Haskell bindings to BoringSSL's cryptographic
primitives via the FFI. BoringSSL is Google's maintained fork of OpenSSL,
battle-tested across Chrome, Android, and Google's infrastructure. These
bindings give Haskell programs access to the same well-audited cryptographic
implementations, wrapped in an API that feels natural in Haskell: pure
interfaces where possible, `ByteString`-based data types throughout, and proper
memory management via `ForeignPtr` finalizers.

If you need cryptographic primitives for a Haskell web server, client, or any
networked application, this library provides the building blocks.

## Modules

| Module | Description |
|---|---|
| `Crypto.BoringSSL.Digest` | Hash functions: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, MD5. One-shot and streaming interfaces. |
| `Crypto.BoringSSL.HMAC` | HMAC message authentication codes with configurable hash algorithm. |
| `Crypto.BoringSSL.AEAD` | Authenticated encryption: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. |
| `Crypto.BoringSSL.HKDF` | HMAC-based key derivation (RFC 5869). Extract, expand, and combined interfaces. |
| `Crypto.BoringSSL.Cipher` | Symmetric ciphers: AES-128/256 in CBC and CTR modes. |
| `Crypto.BoringSSL.Ed25519` | Ed25519 digital signatures: key generation, signing, verification. |
| `Crypto.BoringSSL.X25519` | X25519 Diffie-Hellman key exchange. |
| `Crypto.BoringSSL.ECDSA` | ECDSA signatures over P-256 and P-384 curves. |
| `Crypto.BoringSSL.ECDH` | Elliptic curve Diffie-Hellman key agreement. |
| `Crypto.BoringSSL.RSA` | RSA key generation, PKCS#1 v1.5 and PSS signing, OAEP encryption. |
| `Crypto.BoringSSL.Base64` | Base64 encoding and decoding. |
| `Crypto.BoringSSL.Random` | Cryptographically secure random byte generation. |

## Building

The library compiles BoringSSL from source (included as a Git submodule under
`third_party/boringssl`), so no system-level BoringSSL installation is required.
A C++17 compiler is needed.

```
git clone --recurse-submodules <repo-url>
cd boringssl
cabal build
```

To run the test suite:

```
cabal test
```

## Current status

This library is a work in progress. The cryptographic primitives listed above
are implemented and tested, but you should expect breaking API changes as the
library matures. Contributions and feedback are welcome.
