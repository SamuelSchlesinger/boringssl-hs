{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Scrypt
  ( c_EVP_PBE_scrypt
  ) where

import Foreign.C.Types
import Foreign.Ptr
import Data.Word (Word64)

-- | int EVP_PBE_scrypt(const char *password, size_t password_len,
--                       const uint8_t *salt, size_t salt_len,
--                       uint64_t N, uint64_t r, uint64_t p,
--                       size_t max_mem, uint8_t *out_key, size_t key_len)
foreign import ccall safe "EVP_PBE_scrypt"
  c_EVP_PBE_scrypt :: Ptr CChar -> CSize
                   -> Ptr CUChar -> CSize
                   -> Word64 -> Word64 -> Word64
                   -> CSize
                   -> Ptr CUChar -> CSize
                   -> IO CInt
