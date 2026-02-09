{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.SipHash
  ( c_SIPHASH_24
  ) where

import Data.Word (Word64)
import Foreign.C.Types
import Foreign.Ptr

-- | uint64_t SIPHASH_24(const uint64_t key[2], const uint8_t *input,
--                        size_t input_len)
foreign import ccall unsafe "SIPHASH_24"
  c_SIPHASH_24 :: Ptr Word64 -> Ptr CUChar -> CSize -> IO Word64
