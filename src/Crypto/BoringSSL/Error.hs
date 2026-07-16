-- | The canonical home of 'CryptoError', the error type shared by every
-- fallible operation in this library.
--
-- Import this module (qualified or not) rather than relying on
-- per-primitive re-exports:
--
-- > import Crypto.BoringSSL.Error (CryptoError (..))
--
-- Constructors distinguish the caller-relevant failure classes:
--
--   * 'InvalidInput' — your arguments were rejected before any C call
--     (wrong key length, negative size, …): a caller bug.
--   * 'DecodeError' — externally-supplied bytes failed to parse.
--   * 'AuthenticationFailed' — authenticated decryption detected
--     tampering (or a wrong key\/nonce).
--   * 'BoringSSLError' — BoringSSL reported an error; carries the packed
--     code and drained error-queue messages.
--   * 'OperationFailed' — a C call failed without queue detail.
--   * 'AllocationFailure' — an allocation returned @NULL@.
module Crypto.BoringSSL.Error
  ( CryptoError (..)
  ) where

import Crypto.BoringSSL.Internal.Error (CryptoError (..))
