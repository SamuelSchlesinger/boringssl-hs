{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.Random
  ( c_RAND_bytes
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | int RAND_bytes(uint8_t *buf, size_t len)
-- Uses safe FFI as RAND_bytes may block on entropy.
foreign import capi safe "openssl/rand.h RAND_bytes"
  c_RAND_bytes :: Ptr CUChar -> CSize -> IO CInt
