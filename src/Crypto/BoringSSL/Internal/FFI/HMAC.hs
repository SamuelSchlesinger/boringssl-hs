{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.HMAC
  ( HMAC_CTX
  , c_HMAC
  , c_HMAC_CTX_new
  , c_HMAC_CTX_free
  , c_HMAC_CTX_free_funptr
  , c_HMAC_Init_ex
  , c_HMAC_Update
  , c_HMAC_Final
  ) where

import Crypto.BoringSSL.Internal.FFI.Digest (EVP_MD)
import Foreign.C.Types
import Foreign.Ptr

-- | Opaque type for HMAC_CTX.
data HMAC_CTX

-- | uint8_t *HMAC(const EVP_MD *evp_md, const void *key, size_t key_len,
--                 const uint8_t *data, size_t data_len, uint8_t *out,
--                 unsigned int *out_len)
foreign import ccall unsafe "HMAC"
  c_HMAC :: Ptr EVP_MD -> Ptr CUChar -> CSize
         -> Ptr CUChar -> CSize -> Ptr CUChar -> Ptr CUInt
         -> IO (Ptr CUChar)

-- | HMAC_CTX *HMAC_CTX_new(void)
foreign import ccall unsafe "HMAC_CTX_new"
  c_HMAC_CTX_new :: IO (Ptr HMAC_CTX)

-- | void HMAC_CTX_free(HMAC_CTX *ctx)
foreign import ccall unsafe "HMAC_CTX_free"
  c_HMAC_CTX_free :: Ptr HMAC_CTX -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&HMAC_CTX_free"
  c_HMAC_CTX_free_funptr :: FunPtr (Ptr HMAC_CTX -> IO ())

-- | int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, size_t key_len,
--                    const EVP_MD *md, ENGINE *impl)
foreign import ccall unsafe "HMAC_Init_ex"
  c_HMAC_Init_ex :: Ptr HMAC_CTX -> Ptr CUChar -> CSize -> Ptr EVP_MD -> Ptr () -> IO CInt

-- | int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t data_len)
foreign import ccall unsafe "HMAC_Update"
  c_HMAC_Update :: Ptr HMAC_CTX -> Ptr CUChar -> CSize -> IO CInt

-- | int HMAC_Final(HMAC_CTX *ctx, uint8_t *out, unsigned int *out_len)
foreign import ccall unsafe "HMAC_Final"
  c_HMAC_Final :: Ptr HMAC_CTX -> Ptr CUChar -> Ptr CUInt -> IO CInt
