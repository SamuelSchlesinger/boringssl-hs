{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI
  ( -- * Opaque types
    EVP_MD
  , EVP_AEAD
  , EVP_AEAD_CTX
    -- * Digest FFI
  , c_SHA256
  , c_SHA512
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
    -- * Error handling
  , c_ERR_get_error
  , c_ERR_error_string_n
  , c_ERR_clear_error
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data EVP_MD
data EVP_AEAD
data EVP_AEAD_CTX

-- | uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t out[32])
foreign import ccall unsafe "SHA256"
  c_SHA256 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA512(const uint8_t *data, size_t len, uint8_t out[64])
foreign import ccall unsafe "SHA512"
  c_SHA512 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

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

-- | int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
--     size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
--     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len)
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

-- | int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
--     size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
--     const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len)
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

-- | uint32_t ERR_get_error(void)
foreign import ccall unsafe "ERR_get_error"
  c_ERR_get_error :: IO CUInt

-- | char *ERR_error_string_n(uint32_t packed_error, char *buf, size_t len)
foreign import ccall unsafe "ERR_error_string_n"
  c_ERR_error_string_n :: CUInt -> Ptr CChar -> CSize -> IO (Ptr CChar)

-- | void ERR_clear_error(void)
foreign import ccall unsafe "ERR_clear_error"
  c_ERR_clear_error :: IO ()
