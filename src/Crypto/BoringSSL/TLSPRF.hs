-- | TLS 1.0\/1.2 pseudorandom function (PRF).
--
-- Implements the PRF defined in Section 5 of RFC 5246, used by TLS to
-- derive keying material from a shared secret.
--
-- __This is a legacy primitive__: use it only to interoperate with
-- TLS 1.2-era protocols that specify it. For general key derivation use
-- "Crypto.BoringSSL.HKDF"; for passwords use "Crypto.BoringSSL.PBKDF2"
-- or "Crypto.BoringSSL.Scrypt".
module Crypto.BoringSSL.TLSPRF
  ( tlsPRF
  ) where

import Data.ByteString (ByteString)
import Foreign.Ptr (castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.TLSPRF
import Crypto.BoringSSL.Internal.SecureBytes

-- | Compute the TLS PRF.
--
-- @tlsPRF algo secret label seed1 seed2 outLen@ derives @outLen@ bytes
-- of keying material using the TLS PRF with the given digest @algo@,
-- @secret@, @label@, @seed1@, and @seed2@.
--
-- Returns 'Left' ('InvalidInput') if @outLen@ is not positive.
tlsPRF :: Algorithm -> ByteString -> ByteString -> ByteString -> ByteString -> Int -> Either CryptoError SecureBytes
tlsPRF algo secret label seed1 seed2 outLen
  | outLen <= 0 = Left (InvalidInput "tlsPRF: output length must be positive")
  | otherwise = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString label $ \labelPtr labelLen ->
      withByteString seed1 $ \seed1Ptr seed1Len ->
        withByteString seed2 $ \seed2Ptr seed2Len -> do
          sb <- createSecureBytes outLen $ \_ -> return ()
          rc <- withSecureBytes sb $ \outPtr _ ->
            c_CRYPTO_tls1_prf (ID.evpMD algo)
              (castPtr outPtr) (fromIntegral outLen)
              secretPtr secretLen
              labelPtr labelLen
              seed1Ptr seed1Len
              seed2Ptr seed2Len
          if rc /= 1
            then return (Left (OperationFailed "tlsPRF: derivation failed"))
            else return (Right sb)
{-# NOINLINE tlsPRF #-}
