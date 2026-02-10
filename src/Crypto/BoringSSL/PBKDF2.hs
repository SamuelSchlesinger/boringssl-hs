-- | PBKDF2 password-based key derivation.
--
-- Derives key material from a password and salt using iterated
-- HMAC, as specified in RFC 2898.
module Crypto.BoringSSL.PBKDF2
  ( pbkdf2
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as BSU
import Data.Word (Word32)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.PBKDF2
import Crypto.BoringSSL.Internal.SecureBytes

-- | Derive a key using PBKDF2-HMAC.
--
-- @pbkdf2 algo password salt iterations keyLength@ computes @keyLength@ bytes
-- of key material from @password@ and @salt@ using @iterations@ rounds of
-- PBKDF2 with HMAC using the specified hash @algo@.
pbkdf2 :: Algorithm -> ByteString -> ByteString -> Int -> Int -> Either CryptoError SecureBytes
pbkdf2 algo password salt iterations keyLen
  | keyLen <= 0 = Left (InvalidInput "pbkdf2: key length must be positive")
  | iterations <= 0 = Left (InvalidInput "pbkdf2: iterations must be positive")
  | iterations > fromIntegral (maxBound :: Word32) =
      Left (InvalidInput "pbkdf2: iterations exceeds uint32 maximum")
  | otherwise = unsafePerformIO $
  BSU.unsafeUseAsCStringLen password $ \(passPtr, passLen) ->
    BSU.unsafeUseAsCStringLen salt $ \(saltPtr, saltLen) -> do
      sb <- createSecureBytes keyLen $ \_ -> return ()
      rc <- withSecureBytes sb $ \outPtr _ ->
        c_PKCS5_PBKDF2_HMAC
                passPtr (fromIntegral passLen)
                (castPtr saltPtr) (fromIntegral saltLen)
                (fromIntegral iterations) (ID.evpMD algo)
                (fromIntegral keyLen) (castPtr outPtr)
      if rc /= 1
        then return (Left (OperationFailed "pbkdf2: PKCS5_PBKDF2_HMAC failed"))
        else return (Right sb)
{-# NOINLINE pbkdf2 #-}
