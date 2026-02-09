# Module Review Checklist

Review each module for memory safety, correctness, and idiomatic Haskell.

## Checklist Items

### Memory Safety
- [ ] **MS1: ForeignPtr finalizers** — Heap-allocated C objects are wrapped in `ForeignPtr` with the correct free function; no manual `free` after `newForeignPtr`
- [ ] **MS2: mask/bracket around allocation** — `mask_` or `bracket` protects allocation-then-finalize sequences from async exceptions leaking raw pointers
- [ ] **MS3: No use-after-free** — Pointers obtained via `withForeignPtr` are not used after the callback returns; `ForeignPtr` kept alive for the duration of use
- [ ] **MS4: Buffer bounds** — Output buffers are large enough for worst-case output; variable-length outputs checked against allocated size
- [ ] **MS5: Null-pointer checks** — Every C function that can return `NULL` on failure is checked before use
- [ ] **MS6: Error-path cleanup** — On failure branches, all manually-allocated C resources are freed before returning
- [ ] **MS7: No accidental double-free** — Resources freed manually on error paths are not also attached to a `ForeignPtr`
- [ ] **MS8: Empty-input handling** — Empty `ByteString` inputs yield a non-null pointer (via `withByteString`) or are handled explicitly

### Correctness
- [ ] **C1: Return-code checks** — Every fallible C call's return code is checked; 0/NULL means failure is handled
- [ ] **C2: Error queue drained** — `clearBoringSSLError` called before ops, `getBoringSSLError` after, to avoid stale errors on green-thread migration
- [ ] **C3: Correct constant sizes** — Key sizes, nonce sizes, tag sizes, output sizes match BoringSSL documentation
- [ ] **C4: Output length semantics** — `CSize` out-pointers initialized before call; actual length read after call; not confused with max length
- [ ] **C5: safe vs unsafe ccall** — Long-running or blocking C calls use `safe`; quick, non-blocking calls can use `unsafe`
- [ ] **C6: Correct API usage** — C functions called with correct argument order, correct flag values, correct lifetime assumptions
- [ ] **C7: No partial results on error** — Functions return `Either`/`Maybe`; no partial `ByteString` can leak on failure

### Idiomatic Haskell
- [ ] **H1: Minimal export list** — Module exports only what's needed; internal details are hidden
- [ ] **H2: Consistent error type** — Uses `Either BoringSSLError a` consistently, not mixing exceptions/Maybe/Either
- [ ] **H3: No orphan instances** — No orphan typeclass instances
- [ ] **H4: Naming conventions** — Functions use camelCase; types use PascalCase; names are descriptive
- [ ] **H5: Haddock documentation** — Public functions have doc comments
- [ ] **H6: Pragmas** — `NOINLINE` on `unsafePerformIO`, appropriate strictness annotations
- [ ] **H7: Avoids deep nesting** — Error handling doesn't create excessive rightward drift; uses combinators or early-return patterns where possible

## Modules to Review

### Internal (shared) modules
- [ ] `Crypto.BoringSSL.Internal.Error`
- [ ] `Crypto.BoringSSL.Internal.Buffer`
- [ ] `Crypto.BoringSSL.Internal.Digest`
- [ ] `Crypto.BoringSSL.Internal.ECKey`
- [ ] `Crypto.BoringSSL.Internal.FFI` (main re-export shim)

### FFI binding modules
- [ ] `Crypto.BoringSSL.Internal.FFI.Digest`
- [ ] `Crypto.BoringSSL.Internal.FFI.AEAD`
- [ ] `Crypto.BoringSSL.Internal.FFI.HMAC`
- [ ] `Crypto.BoringSSL.Internal.FFI.HKDF`
- [ ] `Crypto.BoringSSL.Internal.FFI.Random`
- [ ] `Crypto.BoringSSL.Internal.FFI.Cipher`
- [ ] `Crypto.BoringSSL.Internal.FFI.Ed25519`
- [ ] `Crypto.BoringSSL.Internal.FFI.X25519`
- [ ] `Crypto.BoringSSL.Internal.FFI.ECKey`
- [ ] `Crypto.BoringSSL.Internal.FFI.ECDSA`
- [ ] `Crypto.BoringSSL.Internal.FFI.ECDH`
- [ ] `Crypto.BoringSSL.Internal.FFI.RSA`
- [ ] `Crypto.BoringSSL.Internal.FFI.Base64`
- [ ] `Crypto.BoringSSL.Internal.FFI.Memory`
- [ ] `Crypto.BoringSSL.Internal.FFI.PBKDF2`
- [ ] `Crypto.BoringSSL.Internal.FFI.MLKEM`
- [ ] `Crypto.BoringSSL.Internal.FFI.MLDSA`
- [ ] `Crypto.BoringSSL.Internal.FFI.X509`
- [ ] `Crypto.BoringSSL.Internal.FFI.HPKE`
- [ ] `Crypto.BoringSSL.Internal.FFI.SPAKE2`
- [ ] `Crypto.BoringSSL.Internal.FFI.TrustToken`
- [ ] `Crypto.BoringSSL.Internal.FFI.CMAC`
- [ ] `Crypto.BoringSSL.Internal.FFI.SLHDSA`
- [ ] `Crypto.BoringSSL.Internal.FFI.XWing`
- [ ] `Crypto.BoringSSL.Internal.FFI.Scrypt`
- [ ] `Crypto.BoringSSL.Internal.FFI.SipHash`
- [ ] `Crypto.BoringSSL.Internal.FFI.TLSPRF`

### Public API modules
- [ ] `Crypto.BoringSSL.Digest`
- [ ] `Crypto.BoringSSL.AEAD`
- [ ] `Crypto.BoringSSL.HMAC`
- [ ] `Crypto.BoringSSL.HKDF`
- [ ] `Crypto.BoringSSL.Random`
- [ ] `Crypto.BoringSSL.Cipher`
- [ ] `Crypto.BoringSSL.Ed25519`
- [ ] `Crypto.BoringSSL.X25519`
- [ ] `Crypto.BoringSSL.ECDSA`
- [ ] `Crypto.BoringSSL.ECDH`
- [ ] `Crypto.BoringSSL.RSA`
- [ ] `Crypto.BoringSSL.Base64`
- [ ] `Crypto.BoringSSL.PBKDF2`
- [ ] `Crypto.BoringSSL.MLKEM`
- [ ] `Crypto.BoringSSL.MLDSA`
- [ ] `Crypto.BoringSSL.X509`
- [ ] `Crypto.BoringSSL.PEM`
- [ ] `Crypto.BoringSSL.HPKE`
- [ ] `Crypto.BoringSSL.SPAKE2`
- [ ] `Crypto.BoringSSL.TrustToken`
- [ ] `Crypto.BoringSSL.CMAC`
- [ ] `Crypto.BoringSSL.SLHDSA`
- [ ] `Crypto.BoringSSL.XWing`
- [ ] `Crypto.BoringSSL.Scrypt`
- [ ] `Crypto.BoringSSL.SipHash`
- [ ] `Crypto.BoringSSL.TLSPRF`
