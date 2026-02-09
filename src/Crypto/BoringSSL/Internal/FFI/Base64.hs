{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Base64
  ( c_EVP_EncodeBlock
  , c_EVP_EncodedLength
  , c_EVP_DecodeBase64
  , c_EVP_DecodedLength
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | size_t EVP_EncodeBlock(uint8_t *dst, const uint8_t *src, size_t src_len)
foreign import ccall unsafe "EVP_EncodeBlock"
  c_EVP_EncodeBlock :: Ptr CUChar -> Ptr CUChar -> CSize -> IO CSize

-- | int EVP_EncodedLength(size_t *out_len, size_t len)
foreign import ccall unsafe "EVP_EncodedLength"
  c_EVP_EncodedLength :: Ptr CSize -> CSize -> IO CInt

-- | int EVP_DecodeBase64(uint8_t *out, size_t *out_len, size_t max_out,
--                        const uint8_t *in, size_t in_len)
foreign import ccall unsafe "EVP_DecodeBase64"
  c_EVP_DecodeBase64 :: Ptr CUChar -> Ptr CSize -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_DecodedLength(size_t *out_len, size_t len)
foreign import ccall unsafe "EVP_DecodedLength"
  c_EVP_DecodedLength :: Ptr CSize -> CSize -> IO CInt
