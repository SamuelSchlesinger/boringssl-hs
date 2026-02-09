{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Cipher
  ( -- * Opaque types
    EVP_CIPHER
  , EVP_CIPHER_CTX
    -- * Cipher selectors
  , c_EVP_aes_128_cbc
  , c_EVP_aes_256_cbc
  , c_EVP_aes_128_ctr
  , c_EVP_aes_256_ctr
  , c_EVP_aes_128_ecb
  , c_EVP_aes_256_ecb
  , c_EVP_aes_128_ofb
  , c_EVP_aes_256_ofb
    -- * Context lifecycle
  , c_EVP_CIPHER_CTX_new
  , c_EVP_CIPHER_CTX_free
  , c_EVP_CIPHER_CTX_free_funptr
    -- * Encrypt
  , c_EVP_EncryptInit_ex
  , c_EVP_EncryptUpdate_ex
  , c_EVP_EncryptFinal_ex2
    -- * Decrypt
  , c_EVP_DecryptInit_ex
  , c_EVP_DecryptUpdate_ex
  , c_EVP_DecryptFinal_ex2
  ) where

import Foreign.C.Types
import Foreign.Ptr

data EVP_CIPHER
data EVP_CIPHER_CTX

-- Cipher selectors

-- | const EVP_CIPHER *EVP_aes_128_cbc(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_128_cbc"
  c_EVP_aes_128_cbc :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_256_cbc(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_256_cbc"
  c_EVP_aes_256_cbc :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_128_ctr(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_128_ctr"
  c_EVP_aes_128_ctr :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_256_ctr(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_256_ctr"
  c_EVP_aes_256_ctr :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_128_ecb(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_128_ecb"
  c_EVP_aes_128_ecb :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_256_ecb(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_256_ecb"
  c_EVP_aes_256_ecb :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_128_ofb(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_128_ofb"
  c_EVP_aes_128_ofb :: Ptr EVP_CIPHER

-- | const EVP_CIPHER *EVP_aes_256_ofb(void)
foreign import capi unsafe "openssl/cipher.h EVP_aes_256_ofb"
  c_EVP_aes_256_ofb :: Ptr EVP_CIPHER

-- Context lifecycle

-- | EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
foreign import capi unsafe "openssl/cipher.h EVP_CIPHER_CTX_new"
  c_EVP_CIPHER_CTX_new :: IO (Ptr EVP_CIPHER_CTX)

-- | void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
foreign import capi unsafe "openssl/cipher.h EVP_CIPHER_CTX_free"
  c_EVP_CIPHER_CTX_free :: Ptr EVP_CIPHER_CTX -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&EVP_CIPHER_CTX_free"
  c_EVP_CIPHER_CTX_free_funptr :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

-- Encrypt

-- | int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
--                          ENGINE *impl, const uint8_t *key, const uint8_t *iv)
foreign import capi unsafe "openssl/cipher.h EVP_EncryptInit_ex"
  c_EVP_EncryptInit_ex :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Ptr ()
                       -> Ptr CUChar -> Ptr CUChar -> IO CInt

-- | int EVP_EncryptUpdate_ex(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *out_len,
--                            size_t max_out_len, const uint8_t *in, size_t in_len)
foreign import capi unsafe "openssl/cipher.h EVP_EncryptUpdate_ex"
  c_EVP_EncryptUpdate_ex :: Ptr EVP_CIPHER_CTX -> Ptr CUChar -> Ptr CSize
                         -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_EncryptFinal_ex2(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *out_len,
--                            size_t max_out_len)
foreign import capi unsafe "openssl/cipher.h EVP_EncryptFinal_ex2"
  c_EVP_EncryptFinal_ex2 :: Ptr EVP_CIPHER_CTX -> Ptr CUChar -> Ptr CSize
                         -> CSize -> IO CInt

-- Decrypt

-- | int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
--                          ENGINE *impl, const uint8_t *key, const uint8_t *iv)
foreign import capi unsafe "openssl/cipher.h EVP_DecryptInit_ex"
  c_EVP_DecryptInit_ex :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Ptr ()
                       -> Ptr CUChar -> Ptr CUChar -> IO CInt

-- | int EVP_DecryptUpdate_ex(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *out_len,
--                            size_t max_out_len, const uint8_t *in, size_t in_len)
foreign import capi unsafe "openssl/cipher.h EVP_DecryptUpdate_ex"
  c_EVP_DecryptUpdate_ex :: Ptr EVP_CIPHER_CTX -> Ptr CUChar -> Ptr CSize
                         -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_DecryptFinal_ex2(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *out_len,
--                            size_t max_out_len)
foreign import capi unsafe "openssl/cipher.h EVP_DecryptFinal_ex2"
  c_EVP_DecryptFinal_ex2 :: Ptr EVP_CIPHER_CTX -> Ptr CUChar -> Ptr CSize
                         -> CSize -> IO CInt
