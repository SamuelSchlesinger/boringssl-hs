{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.AEAD
  ( -- * Opaque types
    EVP_AEAD
  , EVP_AEAD_CTX
    -- * AEAD algorithm selectors
  , c_EVP_aead_aes_128_gcm
  , c_EVP_aead_aes_256_gcm
  , c_EVP_aead_chacha20_poly1305
    -- * AEAD context lifecycle
  , c_EVP_AEAD_CTX_new
  , c_EVP_AEAD_CTX_free
  , c_EVP_AEAD_CTX_free_funptr
    -- * AEAD seal/open
  , c_EVP_AEAD_CTX_seal
  , c_EVP_AEAD_CTX_open
    -- * AEAD parameter queries
  , c_EVP_AEAD_key_length
  , c_EVP_AEAD_nonce_length
  , c_EVP_AEAD_max_overhead
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data EVP_AEAD
data EVP_AEAD_CTX

-- | const EVP_AEAD *EVP_aead_aes_128_gcm(void)
foreign import ccall unsafe "EVP_aead_aes_128_gcm"
  c_EVP_aead_aes_128_gcm :: Ptr EVP_AEAD

-- | const EVP_AEAD *EVP_aead_aes_256_gcm(void)
foreign import ccall unsafe "EVP_aead_aes_256_gcm"
  c_EVP_aead_aes_256_gcm :: Ptr EVP_AEAD

-- | const EVP_AEAD *EVP_aead_chacha20_poly1305(void)
foreign import ccall unsafe "EVP_aead_chacha20_poly1305"
  c_EVP_aead_chacha20_poly1305 :: Ptr EVP_AEAD

-- | EVP_AEAD_CTX *EVP_AEAD_CTX_new(const EVP_AEAD *aead, const uint8_t *key, size_t key_len, size_t tag_len)
foreign import ccall unsafe "EVP_AEAD_CTX_new"
  c_EVP_AEAD_CTX_new :: Ptr EVP_AEAD -> Ptr CUChar -> CSize -> CSize -> IO (Ptr EVP_AEAD_CTX)

-- | void EVP_AEAD_CTX_free(EVP_AEAD_CTX *ctx)
foreign import ccall unsafe "EVP_AEAD_CTX_free"
  c_EVP_AEAD_CTX_free :: Ptr EVP_AEAD_CTX -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&EVP_AEAD_CTX_free"
  c_EVP_AEAD_CTX_free_funptr :: FunPtr (Ptr EVP_AEAD_CTX -> IO ())

-- | int EVP_AEAD_CTX_seal(...)
foreign import ccall unsafe "EVP_AEAD_CTX_seal"
  c_EVP_AEAD_CTX_seal
    :: Ptr EVP_AEAD_CTX  -- ctx
    -> Ptr CUChar        -- out
    -> Ptr CSize         -- out_len
    -> CSize             -- max_out_len
    -> Ptr CUChar        -- nonce
    -> CSize             -- nonce_len
    -> Ptr CUChar        -- in
    -> CSize             -- in_len
    -> Ptr CUChar        -- ad
    -> CSize             -- ad_len
    -> IO CInt

-- | int EVP_AEAD_CTX_open(...)
foreign import ccall unsafe "EVP_AEAD_CTX_open"
  c_EVP_AEAD_CTX_open
    :: Ptr EVP_AEAD_CTX  -- ctx
    -> Ptr CUChar        -- out
    -> Ptr CSize         -- out_len
    -> CSize             -- max_out_len
    -> Ptr CUChar        -- nonce
    -> CSize             -- nonce_len
    -> Ptr CUChar        -- in (ciphertext)
    -> CSize             -- in_len
    -> Ptr CUChar        -- ad
    -> CSize             -- ad_len
    -> IO CInt

-- | size_t EVP_AEAD_key_length(const EVP_AEAD *aead)
foreign import ccall unsafe "EVP_AEAD_key_length"
  c_EVP_AEAD_key_length :: Ptr EVP_AEAD -> CSize

-- | size_t EVP_AEAD_nonce_length(const EVP_AEAD *aead)
foreign import ccall unsafe "EVP_AEAD_nonce_length"
  c_EVP_AEAD_nonce_length :: Ptr EVP_AEAD -> CSize

-- | size_t EVP_AEAD_max_overhead(const EVP_AEAD *aead)
foreign import ccall unsafe "EVP_AEAD_max_overhead"
  c_EVP_AEAD_max_overhead :: Ptr EVP_AEAD -> CSize
