# API Conventions

This document is the normative specification for boringssl-hs's public API.
Every public module must conform. It was adopted after a survey of the
haskell-cryptography org's sibling libraries (botan, sel/libsodium-bindings),
the wider ecosystem (crypton/`ram`, saltine), libsodium's and OpenSSL's
secure-memory designs, and the org's `STRUCTURE.md` requirements.

## 1. Failure model: three tiers

The tier of an operation follows the *observable behaviour of the underlying
BoringSSL operation*, not implementation convenience:

1. **Deterministic and total → bare value.**
   Same inputs always produce the same output and no input can make the
   operation fail (given types already enforced by smart constructors).
   Implemented with `unsafePerformIO` + `NOINLINE` over the FFI.
   Examples: `hash`, `hmac` on an already-validated key, `verify` (§2).

2. **Deterministic but fallible → pure `Either CryptoError`.**
   Same inputs always produce the same result, but some inputs are rejected.
   Examples: KDFs (parameter validation), parsing/deserialization,
   deterministic signing (Ed25519, RSA PKCS#1 v1.5), AEAD `seal`/`open` with
   an explicit nonce (the context is immutable after creation).

3. **Effectful → `IO` (returning `Either CryptoError a` when fallible).**
   The operation consumes randomness, mutates a context, or reads system
   state. Examples: key generation, `randomBytes`, streaming contexts
   (`digestUpdate`), HPKE seal/open (sequence numbers advance), and
   **randomized signing**: ECDSA, RSA-PSS, ML-DSA and SLH-DSA all draw from
   the CSPRNG per signature, so their `sign` is `IO`. (SLH-DSA signing was
   incorrectly pure before this convention; BoringSSL's implementation is
   randomized per FIPS 205.)

Corollaries:

- `Maybe` is not used as an error channel. Smart constructors return
  `Either CryptoError` so the reason is never discarded.
- No public function calls `error`, `fail`, or silently substitutes a
  default on bad input. Partial behaviour must not exist unless the function
  name carries an `unsafe` prefix (per org STRUCTURE.md).
- We use plain `IO`, not a `MonadRandom`-style class: minimal abstraction,
  matching sel and saltine.

## 2. Verification returns `Bool`, fail-closed

Signature and MAC verification is deterministic and returns bare `Bool`:

```haskell
verify :: PublicKey -> ByteString -> Signature -> Bool
```

Any internal failure folds to `False` (fail-closed). This matches crypton,
botan, sel, and saltine unanimously and eliminates the
`Either CryptoError Bool` shape whose `Right False` was easy to misread as
success. Input-format error detail belongs to smart constructors
(`signatureFromBytes :: ByteString -> Either CryptoError Signature`), not to
`verify`. Where a signature is an unstructured blob (RSA, ECDSA DER),
malformed input simply verifies as `False`.

## 3. Authenticated decryption failure is a distinct error

AEAD `open`, HPKE `recipientOpen`, and anything else that authenticates then
decrypts returns `Either CryptoError plaintext` where tag mismatch is
reported as the dedicated constructor:

```haskell
AuthenticationFailed :: CryptoError
```

Tampering (`Left AuthenticationFailed`) is therefore distinguishable from
caller bugs (`Left (InvalidInput …)`) without string matching. Unverified
plaintext is never returned.

KEMs are different by design: ML-KEM and X-Wing decapsulation uses *implicit
rejection* (FIPS 203) — a well-formed but tampered ciphertext yields
`Right` with a deterministic pseudo-random secret, **not** an error. This
must be documented prominently on every decapsulate function.

## 4. Errors

- `CryptoError` lives canonically in `Crypto.BoringSSL.Error`. Individual
  modules do not re-export it.
- Constructors: `BoringSSLError`, `InvalidInput`, `AllocationFailure`,
  `OperationFailed`, `DecodeError`, `AuthenticationFailed`.
- Any wrapper that can fail on a BoringSSL return code must drain the
  BoringSSL error queue (`checkRCError`, not bare `checkRC`) so diagnostics
  are not discarded, and must clear the queue first on entry.

## 5. Secret material: `SecureBytes`

Canonical module: `Crypto.BoringSSL.SecureBytes`.

- **Allocation**: page-aligned, outside the GC heap, with best-effort
  `mlock` and core-dump exclusion (`MADV_DONTDUMP` on Linux, `VirtualLock`
  on Windows). Lock failure is soft (the allocation proceeds unlocked) —
  matching libsodium and OpenSSL; nobody hard-fails on `RLIMIT_MEMLOCK`.
- **Deallocation**: `OPENSSL_cleanse` of the whole region before unmapping.
- **Instances**: `Eq` is constant-time (`CRYPTO_memcmp`; length mismatch
  short-circuits). `Show` is redacted and shows only the length. No `Ord`,
  no `IsString`.
- **Escape hatch**: `secureBytesToByteString` remains, documented as
  producing an unprotected, GC-managed, non-cleansed copy.
- **Honest threat model** (documented on the module): zero-on-free protects
  against heap-disclosure and post-free memory dumps; mlock keeps secrets
  out of swap; dump exclusion keeps them out of core dumps. None of it
  protects against a same-or-higher-privilege process reading memory,
  DMA/cold-boot attacks, hibernation images, or copies the caller makes via
  the escape hatch.
- Secrets should be *born* secure: key/seed generation returns `SecureBytes`
  (`randomSecureBytes`) or writes directly into secure allocations.
- Derived secrets flow typed, not raw: e.g. HKDF's `hkdfExtract` returns a
  `PRK` newtype (SecureBytes-backed) that `hkdfExpand` accepts directly, so
  the intermediate secret never round-trips through `ByteString`.

## 6. Types

- Every algorithm's public key, private key, and (fixed-format) signature is
  a distinct opaque newtype with smart constructors. Public keys are not
  bare `ByteString`s. Constructors are not exported from public modules.
- Private keys are `SecureBytes`-backed or held in secure foreign
  allocations; their `Show` is redacted; their `Eq` (if any) is
  constant-time.
- Multi-value returns beyond a pair use a record, not a tuple.
- Numeric parameter clusters use a record with a `Default`-style smart
  constructor (e.g. `ScryptParams { scryptN, scryptR, scryptP }`,
  `PBKDF2Params { pbkdf2Iterations }`) so bare `Int`s cannot be transposed.

## 7. Argument order and naming

- Order: **algorithm/context → key material → primary input → auxiliary
  inputs → sizes/options last.** Output length is always the final argument.
- Verification order everywhere: `verify pub msg sig` (context, if any,
  after `sig`). Signing: `sign priv msg ctx`.
- Casing: upper-case acronyms with underscores only where needed for
  legibility — `AES256GCM`, `SHA512_256`, `ChaCha20Poly1305`. Never
  `Aes256Gcm`. (Unanimous across botan, crypton, saltine, sel.)
- Verbs: `seal`/`open` for AEAD-shaped operations (faithful to BoringSSL's
  `EVP_AEAD_CTX_seal/open` and RFC 9180), `encrypt`/`decrypt` for
  unauthenticated or public-key encryption, `sign`/`verify` for signatures,
  `generate…` for randomness-consuming constructors.
- Every algorithm family exposes size constants as functions
  (`publicKeyBytes`, `ciphertextBytes`, …) — no sizes documented only in
  prose or hardcoded in error strings.

## 8. Contexts and concurrency

Every mutable context (digest, HMAC, CMAC, HPKE, SPAKE2, TrustToken) is
serialized with an internal `MVar` and documents that concurrent use is
safe but serialized. Lifecycle misuse (use-after-finalize, out-of-order
protocol steps) returns `Left`, never undefined behaviour.

## 9. Modules

- One module per primitive family, `Crypto.BoringSSL.<Family>`.
- Canonical shared modules: `Crypto.BoringSSL.Error`,
  `Crypto.BoringSSL.SecureBytes`.
- `Crypto.BoringSSL` is a tiny table-of-contents module (Haddock guide
  mapping tasks to modules, plus nothing that can clash).
- Internal modules are not part of the public API contract.

## 10. Documentation

Per org STRUCTURE.md, module documentation must stand alone: state what the
primitive is for, when *not* to use it (with a pointer to the right
alternative — e.g. password hashing belongs to PBKDF2/Scrypt, never Digest
or HKDF), a runnable example, and every security caveat that changes how a
caller should hold the API (nonce reuse, padding oracles, implicit
rejection, constant-time comparison).
