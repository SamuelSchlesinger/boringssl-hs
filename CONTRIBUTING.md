# Contributing to boringssl-hs

Thank you for your interest in contributing!

## Building

```bash
git clone --recurse-submodules https://github.com/haskell-cryptography/boringssl-hs.git
cd boringssl-hs
cabal build
```

To build with assembly optimizations (Linux/macOS, x86_64/aarch64):

```bash
cabal build -fasm
```

## Running tests

```bash
cabal test --test-show-details=direct
```

## Code style

- Haskell2010 with no language extensions unless necessary.
- Follow existing patterns in the codebase: `ByteString`-based APIs, `Either CryptoError a` return types, `ForeignPtr`-based resource management.
- Keep FFI bindings in `Crypto.BoringSSL.Internal.FFI.*` and public APIs in `Crypto.BoringSSL.*`.
- Add Haddock documentation to all public functions.

## Adding a new primitive

1. Add FFI bindings in a new `Crypto.BoringSSL.Internal.FFI.YourPrimitive` module.
2. Add the public API in `Crypto.BoringSSL.YourPrimitive`.
3. Add tests in `test/Test/YourPrimitive.hs` and register the module in `boringssl.cabal`.
4. Include at least: a round-trip property test, a known-answer test (from an RFC or official test vector), and edge-case tests.

## Security considerations

- Cryptographic code changes require careful review. Please describe the security implications of your change in the PR description.
- Use `SecureBytes` for private key material and other secrets that should be zeroed on deallocation.
- Avoid introducing timing side channels: use BoringSSL's constant-time comparison functions rather than `==` on secret data.
- When adding new primitives, include appropriate security guidance in the module-level Haddock documentation.
