{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Random
  ( c_RAND_bytes
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | int RAND_bytes(uint8_t *buf, size_t len)
foreign import ccall unsafe "RAND_bytes"
  c_RAND_bytes :: Ptr CUChar -> CSize -> IO CInt
