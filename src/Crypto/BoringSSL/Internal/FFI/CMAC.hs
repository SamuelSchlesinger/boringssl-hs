{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.CMAC
  ( CMAC_CTX
  , c_AES_CMAC
  , c_CMAC_CTX_new
  , c_CMAC_CTX_free
  , c_CMAC_CTX_free_funptr
  , c_CMAC_Init
  , c_CMAC_Reset
  , c_CMAC_Update
  , c_CMAC_Final
  ) where

import Crypto.BoringSSL.Internal.FFI.Cipher (EVP_CIPHER)
import Foreign.C.Types
import Foreign.Ptr

-- | Opaque type for CMAC_CTX.
data CMAC_CTX

-- | int AES_CMAC(uint8_t out[16], const uint8_t *key, size_t key_len,
--                const uint8_t *in, size_t in_len)
foreign import capi unsafe "openssl/cmac.h AES_CMAC"
  c_AES_CMAC :: Ptr CUChar -> Ptr CUChar -> CSize
             -> Ptr CUChar -> CSize -> IO CInt

-- | CMAC_CTX *CMAC_CTX_new(void)
foreign import capi unsafe "openssl/cmac.h CMAC_CTX_new"
  c_CMAC_CTX_new :: IO (Ptr CMAC_CTX)

-- | void CMAC_CTX_free(CMAC_CTX *ctx)
foreign import capi unsafe "openssl/cmac.h CMAC_CTX_free"
  c_CMAC_CTX_free :: Ptr CMAC_CTX -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&CMAC_CTX_free"
  c_CMAC_CTX_free_funptr :: FunPtr (Ptr CMAC_CTX -> IO ())

-- | int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t key_len,
--                  const EVP_CIPHER *cipher, ENGINE *engine)
foreign import capi unsafe "openssl/cmac.h CMAC_Init"
  c_CMAC_Init :: Ptr CMAC_CTX -> Ptr CUChar -> CSize -> Ptr EVP_CIPHER -> Ptr () -> IO CInt

-- | int CMAC_Reset(CMAC_CTX *ctx)
foreign import capi unsafe "openssl/cmac.h CMAC_Reset"
  c_CMAC_Reset :: Ptr CMAC_CTX -> IO CInt

-- | int CMAC_Update(CMAC_CTX *ctx, const uint8_t *in, size_t in_len)
foreign import capi unsafe "openssl/cmac.h CMAC_Update"
  c_CMAC_Update :: Ptr CMAC_CTX -> Ptr CUChar -> CSize -> IO CInt

-- | int CMAC_Final(CMAC_CTX *ctx, uint8_t *out, size_t *out_len)
foreign import capi unsafe "openssl/cmac.h CMAC_Final"
  c_CMAC_Final :: Ptr CMAC_CTX -> Ptr CUChar -> Ptr CSize -> IO CInt
