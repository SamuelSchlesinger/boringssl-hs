{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Memory
  ( c_OPENSSL_free
  , c_CRYPTO_memcmp
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | void OPENSSL_free(void *ptr)
foreign import ccall unsafe "OPENSSL_free"
  c_OPENSSL_free :: Ptr a -> IO ()

-- | int CRYPTO_memcmp(const void *a, const void *b, size_t len)
-- Returns 0 if equal, non-zero otherwise. Runs in constant time.
foreign import ccall unsafe "CRYPTO_memcmp"
  c_CRYPTO_memcmp :: Ptr a -> Ptr a -> CSize -> IO CInt
