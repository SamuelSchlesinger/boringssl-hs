-- | PBKDF2 password-based key derivation.
--
-- Derives key material from a password and salt using iterated
-- HMAC, as specified in RFC 2898.
module Crypto.BoringSSL.PBKDF2
  ( pbkdf2
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.PBKDF2

-- | Derive a key using PBKDF2-HMAC.
--
-- @pbkdf2 algo password salt iterations keyLength@ computes @keyLength@ bytes
-- of key material from @password@ and @salt@ using @iterations@ rounds of
-- PBKDF2 with HMAC using the specified hash @algo@.
pbkdf2 :: Algorithm -> ByteString -> ByteString -> Int -> Int -> Either CryptoError ByteString
pbkdf2 algo password salt iterations keyLen = unsafePerformIO $
  BSU.unsafeUseAsCStringLen password $ \(passPtr, passLen) ->
    withByteString salt $ \saltPtr saltLen -> do
      fptr <- BSI.mallocByteString keyLen
      rc <- withForeignPtr fptr $ \outPtr ->
        c_PKCS5_PBKDF2_HMAC
                passPtr (fromIntegral passLen)
                saltPtr saltLen
                (fromIntegral iterations) (ID.evpMD algo)
                (fromIntegral keyLen) (castPtr outPtr)
      if rc /= 1
        then return (Left (OperationFailed "pbkdf2: PKCS5_PBKDF2_HMAC failed"))
        else return (Right (BSI.BS fptr keyLen))
{-# NOINLINE pbkdf2 #-}
