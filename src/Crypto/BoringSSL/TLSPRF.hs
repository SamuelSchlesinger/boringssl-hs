-- | TLS 1.0\/1.2 pseudorandom function (PRF).
--
-- Implements the PRF defined in Section 5 of RFC 5246, used by TLS
-- to derive keying material from a shared secret.
module Crypto.BoringSSL.TLSPRF
  ( tlsPRF
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr (castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.TLSPRF

-- | Compute the TLS PRF.
--
-- @tlsPRF algo outLen secret label seed1 seed2@ derives @outLen@ bytes
-- of keying material using the TLS PRF with the given digest @algo@,
-- @secret@, @label@, @seed1@, and @seed2@.
--
-- Returns 'Left' on failure.
tlsPRF :: Algorithm -> Int -> ByteString -> ByteString -> ByteString -> ByteString -> Either CryptoError ByteString
tlsPRF algo outLen secret label seed1 seed2 = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString label $ \labelPtr labelLen ->
      withByteString seed1 $ \seed1Ptr seed1Len ->
        withByteString seed2 $ \seed2Ptr seed2Len -> do
          fptr <- BSI.mallocByteString outLen
          rc <- withForeignPtr fptr $ \outPtr ->
            c_CRYPTO_tls1_prf (ID.evpMD algo)
              (castPtr outPtr) (fromIntegral outLen)
              secretPtr secretLen
              labelPtr labelLen
              seed1Ptr seed1Len
              seed2Ptr seed2Len
          if rc /= 1
            then return (Left (OperationFailed "tlsPRF: derivation failed"))
            else return (Right (BSI.BS fptr outLen))
{-# NOINLINE tlsPRF #-}
