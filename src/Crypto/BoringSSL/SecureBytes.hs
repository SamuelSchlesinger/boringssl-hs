-- | The canonical home of 'SecureBytes', hardened storage for secret
-- material. See 'Crypto.BoringSSL.Internal.SecureBytes' for the precise
-- guarantees and threat model; in short: page-aligned allocation outside
-- the GC heap, best-effort @mlock@\/@VirtualLock@ and core-dump
-- exclusion, and @OPENSSL_cleanse@ before release. 'Eq' is
-- constant-time; 'Show' reveals only the length.
--
-- Prefer keeping secrets inside 'SecureBytes' end-to-end.
-- 'secureBytesToByteString' exists for interoperability but produces an
-- ordinary, unprotected copy.
module Crypto.BoringSSL.SecureBytes
  ( SecureBytes
  , createSecureBytes
  , secureBytesLength
  , secureBytesToByteString
  , secureBytesEq
  ) where

import Crypto.BoringSSL.Internal.SecureBytes
