{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Memory
  ( c_OPENSSL_free
  ) where

import Foreign.Ptr

-- | void OPENSSL_free(void *ptr)
foreign import ccall unsafe "OPENSSL_free"
  c_OPENSSL_free :: Ptr a -> IO ()
