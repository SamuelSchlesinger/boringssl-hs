{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.PBKDF2
  ( c_PKCS5_PBKDF2_HMAC
  ) where

import Crypto.BoringSSL.Internal.FFI.Digest (EVP_MD)
import Foreign.C.Types
import Foreign.Ptr

-- | int PKCS5_PBKDF2_HMAC(const char *password, size_t password_len,
--                          const uint8_t *salt, size_t salt_len,
--                          uint32_t iterations, const EVP_MD *digest,
--                          size_t key_len, uint8_t *out_key)
foreign import ccall unsafe "PKCS5_PBKDF2_HMAC"
  c_PKCS5_PBKDF2_HMAC :: Ptr CChar -> CSize
                       -> Ptr CUChar -> CSize
                       -> CUInt -> Ptr EVP_MD
                       -> CSize -> Ptr CUChar
                       -> IO CInt
