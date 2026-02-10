{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.Memory
  ( c_OPENSSL_free
  , c_OPENSSL_cleanse
  , c_CRYPTO_memcmp
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | void OPENSSL_free(void *ptr)
foreign import capi unsafe "openssl/mem.h OPENSSL_free"
  c_OPENSSL_free :: Ptr a -> IO ()

-- | void OPENSSL_cleanse(void *ptr, size_t len)
-- Overwrites |len| bytes of memory at |ptr| with zeros, in a way that
-- the compiler cannot optimize away (unlike a plain memset).
foreign import capi unsafe "openssl/mem.h OPENSSL_cleanse"
  c_OPENSSL_cleanse :: Ptr a -> CSize -> IO ()

-- | int CRYPTO_memcmp(const void *a, const void *b, size_t len)
-- Returns 0 if equal, non-zero otherwise. Runs in constant time.
foreign import capi unsafe "openssl/crypto.h CRYPTO_memcmp"
  c_CRYPTO_memcmp :: Ptr a -> Ptr a -> CSize -> IO CInt
