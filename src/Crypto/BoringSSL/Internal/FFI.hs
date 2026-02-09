{-# LANGUAGE ForeignFunctionInterface #-}
-- | Backward-compatible re-export shim. New code should import the
-- per-domain FFI modules directly.
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
  , c_EVP_aead_aes_128_gcm_siv
  , c_EVP_aead_aes_256_gcm_siv
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

import Crypto.BoringSSL.Internal.FFI.Digest
  ( EVP_MD, c_SHA256, c_SHA512 )
import Crypto.BoringSSL.Internal.FFI.AEAD

import Foreign.C.Types
import Foreign.Ptr

-- | uint32_t ERR_get_error(void)
foreign import ccall unsafe "ERR_get_error"
  c_ERR_get_error :: IO CUInt

-- | char *ERR_error_string_n(uint32_t packed_error, char *buf, size_t len)
foreign import ccall unsafe "ERR_error_string_n"
  c_ERR_error_string_n :: CUInt -> Ptr CChar -> CSize -> IO (Ptr CChar)

-- | void ERR_clear_error(void)
foreign import ccall unsafe "ERR_clear_error"
  c_ERR_clear_error :: IO ()
