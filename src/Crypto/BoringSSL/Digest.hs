module Crypto.BoringSSL.Digest
  ( Algorithm(..)
  , hash
  , hashSHA256
  , hashSHA512
  ) where

import Data.ByteString (ByteString)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI

-- | Supported hash algorithms.
data Algorithm = SHA256 | SHA512
  deriving (Eq, Show)

-- | Hash a ByteString using the specified algorithm.
hash :: Algorithm -> ByteString -> ByteString
hash SHA256 = hashSHA256
hash SHA512 = hashSHA512

-- | Compute the SHA-256 hash of a ByteString.
hashSHA256 :: ByteString -> ByteString
hashSHA256 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 32 $ \outPtr ->
      c_SHA256 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA256 #-}

-- | Compute the SHA-512 hash of a ByteString.
hashSHA512 :: ByteString -> ByteString
hashSHA512 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 64 $ \outPtr ->
      c_SHA512 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA512 #-}
