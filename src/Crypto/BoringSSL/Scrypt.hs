-- | Scrypt password-based key derivation.
--
-- Derives key material from a password and salt using the scrypt
-- algorithm, as specified in RFC 7914.
module Crypto.BoringSSL.Scrypt
  ( scrypt
  , CryptoError(..)
  ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Data.Word (Word64)
import Foreign.ForeignPtr
import Foreign.Ptr (castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Scrypt

-- | Derive a key using scrypt.
--
-- @scrypt password salt n r p keyLen@ computes @keyLen@ bytes of key
-- material from @password@ and @salt@ using the scrypt parameters @n@
-- (CPU\/memory cost), @r@ (block size), and @p@ (parallelization).
--
-- Returns 'Left' on failure (e.g. invalid parameters).
scrypt :: ByteString -> ByteString -> Word64 -> Word64 -> Word64 -> Int -> Either CryptoError ByteString
scrypt password salt n r p keyLen
  | keyLen <= 0 = Left (InvalidInput "scrypt: key length must be positive")
  | n < 2 || (n .&. (n - 1)) /= 0 = Left (InvalidInput "scrypt: N must be >= 2 and a power of 2")
  | r == 0 = Left (InvalidInput "scrypt: r must be > 0")
  | p == 0 = Left (InvalidInput "scrypt: p must be > 0")
  | otherwise = unsafePerformIO $
  BSU.unsafeUseAsCStringLen password $ \(passPtr, passLen) ->
    withByteString salt $ \saltPtr saltLen -> do
      fptr <- BSI.mallocByteString keyLen
      rc <- withForeignPtr fptr $ \outPtr ->
        c_EVP_PBE_scrypt
          passPtr (fromIntegral passLen)
          saltPtr saltLen
          n r p 0
          (castPtr outPtr) (fromIntegral keyLen)
      if rc /= 1
        then return (Left (OperationFailed "scrypt: derivation failed"))
        else return (Right (BSI.BS fptr keyLen))
{-# NOINLINE scrypt #-}
