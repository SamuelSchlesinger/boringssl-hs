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
