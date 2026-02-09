{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.HKDF
  ( c_HKDF
  , c_HKDF_extract
  , c_HKDF_expand
  ) where

import Crypto.BoringSSL.Internal.FFI.Digest (EVP_MD)
import Foreign.C.Types
import Foreign.Ptr

-- | int HKDF(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
--            const uint8_t *secret, size_t secret_len,
--            const uint8_t *salt, size_t salt_len,
--            const uint8_t *info, size_t info_len)
foreign import capi unsafe "openssl/hkdf.h HKDF"
  c_HKDF :: Ptr CUChar -> CSize -> Ptr EVP_MD
         -> Ptr CUChar -> CSize
         -> Ptr CUChar -> CSize
         -> Ptr CUChar -> CSize
         -> IO CInt

-- | int HKDF_extract(uint8_t *out_key, size_t *out_len, const EVP_MD *digest,
--                    const uint8_t *secret, size_t secret_len,
--                    const uint8_t *salt, size_t salt_len)
foreign import capi unsafe "openssl/hkdf.h HKDF_extract"
  c_HKDF_extract :: Ptr CUChar -> Ptr CSize -> Ptr EVP_MD
                 -> Ptr CUChar -> CSize
                 -> Ptr CUChar -> CSize
                 -> IO CInt

-- | int HKDF_expand(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
--                   const uint8_t *prk, size_t prk_len,
--                   const uint8_t *info, size_t info_len)
foreign import capi unsafe "openssl/hkdf.h HKDF_expand"
  c_HKDF_expand :: Ptr CUChar -> CSize -> Ptr EVP_MD
                -> Ptr CUChar -> CSize
                -> Ptr CUChar -> CSize
                -> IO CInt
