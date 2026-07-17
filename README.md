# boringssl

[![CI](https://github.com/haskell-cryptography/boringssl-hs/actions/workflows/ci.yml/badge.svg)](https://github.com/haskell-cryptography/boringssl-hs/actions/workflows/ci.yml)

Haskell bindings to Google's [BoringSSL](https://boringssl.googlesource.com/boringssl/) cryptography library.

> **Warning:** This library is experimental and under active construction. The API
> is unstable and may change without notice. Do not use this in production systems.

## Overview

This library wraps BoringSSL's cryptographic primitives via the FFI. BoringSSL
is Google's fork of OpenSSL — the same code Google ships in Chrome and Android.
The bindings expose those implementations to Haskell with pure interfaces where
the underlying operation is deterministic, `ByteString`-based types throughout,
and `ForeignPtr` finalizers for memory management.

## Supported GHC versions

| GHC     | Linux | macOS | Windows |
|---------|-------|-------|---------|
| 9.6.x   | Yes   | Yes   | Yes     |
| 9.8.x   | Yes   | Yes   | —       |
| 9.10.x  | Yes   | Yes   | —       |
| 9.12.x  | Yes   | Yes   | —       |

## Features

**Hash functions** — SHA-1, SHA-2 (224/256/384/512/512-256), MD5, BLAKE2b-256.
One-shot and streaming APIs.

**MACs** — HMAC (all hash algorithms), CMAC (AES-128/256), SipHash.

**Key derivation** — HKDF, PBKDF2, scrypt, TLS PRF.

**Authenticated encryption (AEAD)** — AES-GCM (128/192/256),
ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV, AES-CTR-HMAC-SHA256,
AES-EAX, AES-CCM.

**Symmetric ciphers** — AES-128/256 in CBC, CTR, ECB, and OFB modes.

**Asymmetric cryptography** — Ed25519, X25519, ECDSA (P-256/P-384/P-521),
ECDH, RSA (sign/verify/encrypt with PSS, PKCS#1 v1.5, and OAEP).

**Post-quantum** — ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+),
X-Wing (X25519 + ML-KEM-768 hybrid).

**Protocols** — HPKE (RFC 9180), SPAKE2, TrustToken.

**Encoding & PKI** — Base64, PEM, X.509 parsing, private key
serialization.

## Quick start

Start at [`Crypto.BoringSSL`](src/Crypto/BoringSSL.hs) — a Haddock-only
module mapping tasks to the module that does them. Import the
primitive-specific modules you need; several share function names by
design, so qualified imports are recommended.

```haskell
{-# LANGUAGE OverloadedStrings #-}
import qualified Crypto.BoringSSL.AEAD as AEAD
import qualified Crypto.BoringSSL.Digest as Digest
import qualified Crypto.BoringSSL.Random as Random

-- Hashing is pure and total.
digest :: ByteString
digest = Digest.hashSHA256 "hello, world"

-- Authenticated encryption with AES-256-GCM.
main :: IO ()
main = do
  key <- Random.randomBytes (AEAD.keyLength AEAD.AES256GCM)
  ctx <- either (error . show) pure =<< AEAD.newAEADCtx AEAD.AES256GCM key
  -- Never reuse a nonce with the same key.
  nonce <- AEAD.generateNonce AEAD.AES256GCM
  let ad = "associated data"        -- authenticated, not encrypted
  ciphertext <- either (error . show) pure (AEAD.seal ctx nonce "secret message" ad)
  case AEAD.open ctx nonce ciphertext ad of
    Left err        -> error (show err)   -- AuthenticationFailed if tampered
    Right plaintext -> print plaintext    -- "secret message"
```

This example is compiled and executed as part of the test suite
(`test/Test/Readme.hs`), so it cannot drift from the real API.

Password hashing needs a *slow* KDF, never a plain hash:

```haskell
import qualified Crypto.BoringSSL.Scrypt as Scrypt
import qualified Crypto.BoringSSL.Random as Random

hashPassword :: ByteString -> IO (Either CryptoError SecureBytes)
hashPassword password = do
  salt <- Random.randomBytes 16
  pure (Scrypt.scrypt password salt Scrypt.defaultScryptParams)
```

## Building

The library compiles BoringSSL from source (included as a Git submodule under
`third_party/boringssl`), so no system-level BoringSSL installation is required.
You will need a C++17 compiler (`g++` or `clang++`).

```
git clone --recurse-submodules https://github.com/haskell-cryptography/boringssl-hs.git
cd boringssl-hs
cabal build
```

To run the test suite:

```
cabal test
```

### Assembly optimizations

By default, BoringSSL is compiled with portable C fallback implementations.
On x86\_64 and aarch64 (Linux and macOS), you can enable hand-written assembly
optimizations for improved performance and stronger constant-time guarantees:

```
cabal build -fasm
```

The `-fasm` flag enables optimized routines for AES, SHA, ChaCha20, Poly1305,
P-256, and Montgomery multiplication. On unsupported platforms, the flag is
silently ignored.

### Platform notes

- **Linux**: Requires `g++` (or `clang++`) and `libstdc++`. Tested on x86\_64
  and aarch64.
- **macOS**: Requires `clang++` (Xcode command-line tools). Tested on Apple
  Silicon and Intel.
- **Windows**: Assembly optimizations are not available. The C++ runtime is
  linked via GHC's own `system-cxx-std-lib`, matching its Clang toolchain.

## Security considerations

- **Nonce management**: AES-GCM nonce reuse is catastrophic — it completely
  destroys both confidentiality and authenticity. Use `generateNonce` for
  random nonces, or use AES-GCM-SIV for nonce-misuse resistance.
- **Constant-time operations**: BoringSSL provides constant-time
  implementations for sensitive operations. Enabling `-fasm` provides stronger
  constant-time guarantees via hand-written assembly.
- **Secure memory**: Secret material lives in `SecureBytes`: page-aligned
  allocation outside the GC heap, best-effort `mlock`/`VirtualLock` and
  core-dump exclusion, and `OPENSSL_cleanse` before release, with a
  constant-time `Eq` and a redacted `Show`. This protects against secrets
  lingering in reusable memory, reaching swap, or landing in core dumps —
  not against a same-privilege process reading live memory, hibernation
  images, or copies you make with `secureBytesToByteString`.
- **Passwords**: use `PBKDF2` or `Scrypt` (memory-hard, start from
  `defaultScryptParams`). Never `Digest` or `HKDF` — plain hashes and HKDF
  assume high-entropy input and are brute-forceable at billions of guesses
  per second.
- **Verification**: signature and MAC verification returns a plain `Bool`
  and fails closed, so a `False` can never be mistaken for success.
- **Post-quantum KEMs**: ML-KEM and X-Wing use FIPS 203 implicit
  rejection — a tampered ciphertext decapsulates to a *different* secret
  rather than an error. Detect it via the AEAD step that follows.
- **Unauthenticated ciphers**: The `Cipher` module (AES-CBC, CTR, ECB, OFB)
  does **not** provide integrity protection. Prefer AEAD ciphers for
  encryption.
- **PKCS#1 v1.5 encryption**: The RSA PKCS#1 v1.5 encryption functions are
  deprecated due to Bleichenbacher-style attacks. Use OAEP instead.

## API conventions

The public API follows a written specification — see
[CONVENTIONS.md](CONVENTIONS.md). In short: purity tracks the underlying
operation (total, pure-fallible via `Either CryptoError`, or `IO` when
randomness or mutable state is involved); verification returns fail-closed
`Bool`; errors are one `CryptoError` type from `Crypto.BoringSSL.Error`;
secrets live in `SecureBytes` from `Crypto.BoringSSL.SecureBytes`.

## Governance

This project is part of the [haskell-cryptography](https://github.com/haskell-cryptography)
organization. See [STRUCTURE.md](https://github.com/haskell-cryptography/governance/blob/main/STRUCTURE.md)
for governance details.

## Disclaimer

This is not an officially supported Google product.

## Current status

This library is a work in progress. The cryptographic primitives listed above
are implemented and tested, but you should expect breaking API changes as the
library matures. Contributions and feedback are welcome.
