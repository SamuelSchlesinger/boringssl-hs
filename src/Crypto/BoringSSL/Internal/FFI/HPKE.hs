{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.HPKE
  ( -- * Opaque types
    EVP_HPKE_KEM
  , EVP_HPKE_KDF
  , EVP_HPKE_AEAD
  , EVP_HPKE_KEY
  , EVP_HPKE_CTX
    -- * Constants
  , evpHPKEMaxPublicKeyLength
  , evpHPKEMaxPrivateKeyLength
  , evpHPKEMaxEncLength
  , evpHPKEMaxOverhead
    -- * KEM selectors
  , c_EVP_hpke_x25519_hkdf_sha256
  , c_EVP_hpke_p256_hkdf_sha256
  , c_EVP_hpke_xwing
  , c_EVP_hpke_mlkem768
  , c_EVP_hpke_mlkem1024
    -- * KDF selectors
  , c_EVP_hpke_hkdf_sha256
    -- * AEAD selectors
  , c_EVP_hpke_aes_128_gcm
  , c_EVP_hpke_aes_256_gcm
  , c_EVP_hpke_chacha20_poly1305
    -- * Key lifecycle
  , c_EVP_HPKE_KEY_new
  , c_EVP_HPKE_KEY_free
  , c_EVP_HPKE_KEY_free_funptr
  , c_EVP_HPKE_KEY_generate
  , c_EVP_HPKE_KEY_init
  , c_EVP_HPKE_KEY_public_key
  , c_EVP_HPKE_KEY_private_key
    -- * Context lifecycle
  , c_EVP_HPKE_CTX_new
  , c_EVP_HPKE_CTX_free
  , c_EVP_HPKE_CTX_free_funptr
    -- * Setup
  , c_EVP_HPKE_CTX_setup_sender
  , c_EVP_HPKE_CTX_setup_recipient
  , c_EVP_HPKE_CTX_setup_auth_sender
  , c_EVP_HPKE_CTX_setup_auth_recipient
    -- * Operations
  , c_EVP_HPKE_CTX_seal
  , c_EVP_HPKE_CTX_open
  , c_EVP_HPKE_CTX_export
  , c_EVP_HPKE_CTX_max_overhead
    -- * Query
  , c_EVP_HPKE_KEM_public_key_len
  , c_EVP_HPKE_KEM_private_key_len
  , c_EVP_HPKE_KEM_enc_len
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data EVP_HPKE_KEM
data EVP_HPKE_KDF
data EVP_HPKE_AEAD
data EVP_HPKE_KEY
data EVP_HPKE_CTX

-- Constants from hpke.h
evpHPKEMaxPublicKeyLength :: Int
evpHPKEMaxPublicKeyLength = 1568

evpHPKEMaxPrivateKeyLength :: Int
evpHPKEMaxPrivateKeyLength = 64

evpHPKEMaxEncLength :: Int
evpHPKEMaxEncLength = 1568

evpHPKEMaxOverhead :: Int
evpHPKEMaxOverhead = 64

-- KEM selectors

-- | const EVP_HPKE_KEM *EVP_hpke_x25519_hkdf_sha256(void)
foreign import ccall unsafe "EVP_hpke_x25519_hkdf_sha256"
  c_EVP_hpke_x25519_hkdf_sha256 :: Ptr EVP_HPKE_KEM

-- | const EVP_HPKE_KEM *EVP_hpke_p256_hkdf_sha256(void)
foreign import ccall unsafe "EVP_hpke_p256_hkdf_sha256"
  c_EVP_hpke_p256_hkdf_sha256 :: Ptr EVP_HPKE_KEM

-- | const EVP_HPKE_KEM *EVP_hpke_xwing(void)
foreign import ccall unsafe "EVP_hpke_xwing"
  c_EVP_hpke_xwing :: Ptr EVP_HPKE_KEM

-- | const EVP_HPKE_KEM *EVP_hpke_mlkem768(void)
foreign import ccall unsafe "EVP_hpke_mlkem768"
  c_EVP_hpke_mlkem768 :: Ptr EVP_HPKE_KEM

-- | const EVP_HPKE_KEM *EVP_hpke_mlkem1024(void)
foreign import ccall unsafe "EVP_hpke_mlkem1024"
  c_EVP_hpke_mlkem1024 :: Ptr EVP_HPKE_KEM

-- KDF selectors

-- | const EVP_HPKE_KDF *EVP_hpke_hkdf_sha256(void)
foreign import ccall unsafe "EVP_hpke_hkdf_sha256"
  c_EVP_hpke_hkdf_sha256 :: Ptr EVP_HPKE_KDF

-- AEAD selectors

-- | const EVP_HPKE_AEAD *EVP_hpke_aes_128_gcm(void)
foreign import ccall unsafe "EVP_hpke_aes_128_gcm"
  c_EVP_hpke_aes_128_gcm :: Ptr EVP_HPKE_AEAD

-- | const EVP_HPKE_AEAD *EVP_hpke_aes_256_gcm(void)
foreign import ccall unsafe "EVP_hpke_aes_256_gcm"
  c_EVP_hpke_aes_256_gcm :: Ptr EVP_HPKE_AEAD

-- | const EVP_HPKE_AEAD *EVP_hpke_chacha20_poly1305(void)
foreign import ccall unsafe "EVP_hpke_chacha20_poly1305"
  c_EVP_hpke_chacha20_poly1305 :: Ptr EVP_HPKE_AEAD

-- Key lifecycle

-- | EVP_HPKE_KEY *EVP_HPKE_KEY_new(void)
foreign import ccall unsafe "EVP_HPKE_KEY_new"
  c_EVP_HPKE_KEY_new :: IO (Ptr EVP_HPKE_KEY)

-- | void EVP_HPKE_KEY_free(EVP_HPKE_KEY *key)
foreign import ccall unsafe "EVP_HPKE_KEY_free"
  c_EVP_HPKE_KEY_free :: Ptr EVP_HPKE_KEY -> IO ()

-- | FunPtr for EVP_HPKE_KEY_free finalizer
foreign import ccall unsafe "&EVP_HPKE_KEY_free"
  c_EVP_HPKE_KEY_free_funptr :: FunPtr (Ptr EVP_HPKE_KEY -> IO ())

-- | int EVP_HPKE_KEY_generate(EVP_HPKE_KEY *key, const EVP_HPKE_KEM *kem)
foreign import ccall unsafe "EVP_HPKE_KEY_generate"
  c_EVP_HPKE_KEY_generate :: Ptr EVP_HPKE_KEY -> Ptr EVP_HPKE_KEM -> IO CInt

-- | int EVP_HPKE_KEY_init(EVP_HPKE_KEY *key, const EVP_HPKE_KEM *kem,
--                         const uint8_t *priv_key, size_t priv_key_len)
foreign import ccall unsafe "EVP_HPKE_KEY_init"
  c_EVP_HPKE_KEY_init :: Ptr EVP_HPKE_KEY -> Ptr EVP_HPKE_KEM
                       -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_HPKE_KEY_public_key(const EVP_HPKE_KEY *key, uint8_t *out,
--                               size_t *out_len, size_t max_out)
foreign import ccall unsafe "EVP_HPKE_KEY_public_key"
  c_EVP_HPKE_KEY_public_key :: Ptr EVP_HPKE_KEY -> Ptr CUChar
                             -> Ptr CSize -> CSize -> IO CInt

-- | int EVP_HPKE_KEY_private_key(const EVP_HPKE_KEY *key, uint8_t *out,
--                                size_t *out_len, size_t max_out)
foreign import ccall unsafe "EVP_HPKE_KEY_private_key"
  c_EVP_HPKE_KEY_private_key :: Ptr EVP_HPKE_KEY -> Ptr CUChar
                              -> Ptr CSize -> CSize -> IO CInt

-- Context lifecycle

-- | EVP_HPKE_CTX *EVP_HPKE_CTX_new(void)
foreign import ccall unsafe "EVP_HPKE_CTX_new"
  c_EVP_HPKE_CTX_new :: IO (Ptr EVP_HPKE_CTX)

-- | void EVP_HPKE_CTX_free(EVP_HPKE_CTX *ctx)
foreign import ccall unsafe "EVP_HPKE_CTX_free"
  c_EVP_HPKE_CTX_free :: Ptr EVP_HPKE_CTX -> IO ()

-- | FunPtr for EVP_HPKE_CTX_free finalizer
foreign import ccall unsafe "&EVP_HPKE_CTX_free"
  c_EVP_HPKE_CTX_free_funptr :: FunPtr (Ptr EVP_HPKE_CTX -> IO ())

-- Setup

-- | int EVP_HPKE_CTX_setup_sender(
--     EVP_HPKE_CTX *ctx, uint8_t *out_enc, size_t *out_enc_len, size_t max_enc,
--     const EVP_HPKE_KEM *kem, const EVP_HPKE_KDF *kdf, const EVP_HPKE_AEAD *aead,
--     const uint8_t *peer_public_key, size_t peer_public_key_len,
--     const uint8_t *info, size_t info_len)
foreign import ccall unsafe "EVP_HPKE_CTX_setup_sender"
  c_EVP_HPKE_CTX_setup_sender
    :: Ptr EVP_HPKE_CTX -> Ptr CUChar -> Ptr CSize -> CSize
    -> Ptr EVP_HPKE_KEM -> Ptr EVP_HPKE_KDF -> Ptr EVP_HPKE_AEAD
    -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize
    -> IO CInt

-- | int EVP_HPKE_CTX_setup_recipient(
--     EVP_HPKE_CTX *ctx, const EVP_HPKE_KEY *key, const EVP_HPKE_KDF *kdf,
--     const EVP_HPKE_AEAD *aead, const uint8_t *enc, size_t enc_len,
--     const uint8_t *info, size_t info_len)
foreign import ccall unsafe "EVP_HPKE_CTX_setup_recipient"
  c_EVP_HPKE_CTX_setup_recipient
    :: Ptr EVP_HPKE_CTX -> Ptr EVP_HPKE_KEY -> Ptr EVP_HPKE_KDF
    -> Ptr EVP_HPKE_AEAD -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize
    -> IO CInt

-- | int EVP_HPKE_CTX_setup_auth_sender(
--     EVP_HPKE_CTX *ctx, uint8_t *out_enc, size_t *out_enc_len, size_t max_enc,
--     const EVP_HPKE_KEY *key, const EVP_HPKE_KDF *kdf, const EVP_HPKE_AEAD *aead,
--     const uint8_t *peer_public_key, size_t peer_public_key_len,
--     const uint8_t *info, size_t info_len)
foreign import ccall unsafe "EVP_HPKE_CTX_setup_auth_sender"
  c_EVP_HPKE_CTX_setup_auth_sender
    :: Ptr EVP_HPKE_CTX -> Ptr CUChar -> Ptr CSize -> CSize
    -> Ptr EVP_HPKE_KEY -> Ptr EVP_HPKE_KDF -> Ptr EVP_HPKE_AEAD
    -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize
    -> IO CInt

-- | int EVP_HPKE_CTX_setup_auth_recipient(
--     EVP_HPKE_CTX *ctx, const EVP_HPKE_KEY *key, const EVP_HPKE_KDF *kdf,
--     const EVP_HPKE_AEAD *aead, const uint8_t *enc, size_t enc_len,
--     const uint8_t *info, size_t info_len,
--     const uint8_t *peer_public_key, size_t peer_public_key_len)
foreign import ccall unsafe "EVP_HPKE_CTX_setup_auth_recipient"
  c_EVP_HPKE_CTX_setup_auth_recipient
    :: Ptr EVP_HPKE_CTX -> Ptr EVP_HPKE_KEY -> Ptr EVP_HPKE_KDF
    -> Ptr EVP_HPKE_AEAD -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize
    -> IO CInt

-- Operations

-- | int EVP_HPKE_CTX_seal(EVP_HPKE_CTX *ctx, uint8_t *out,
--                         size_t *out_len, size_t max_out_len,
--                         const uint8_t *in, size_t in_len,
--                         const uint8_t *ad, size_t ad_len)
foreign import ccall unsafe "EVP_HPKE_CTX_seal"
  c_EVP_HPKE_CTX_seal
    :: Ptr EVP_HPKE_CTX -> Ptr CUChar -> Ptr CSize -> CSize
    -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_HPKE_CTX_open(EVP_HPKE_CTX *ctx, uint8_t *out,
--                         size_t *out_len, size_t max_out_len,
--                         const uint8_t *in, size_t in_len,
--                         const uint8_t *ad, size_t ad_len)
foreign import ccall unsafe "EVP_HPKE_CTX_open"
  c_EVP_HPKE_CTX_open
    :: Ptr EVP_HPKE_CTX -> Ptr CUChar -> Ptr CSize -> CSize
    -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_HPKE_CTX_export(const EVP_HPKE_CTX *ctx, uint8_t *out,
--                           size_t secret_len,
--                           const uint8_t *context, size_t context_len)
foreign import ccall unsafe "EVP_HPKE_CTX_export"
  c_EVP_HPKE_CTX_export
    :: Ptr EVP_HPKE_CTX -> Ptr CUChar -> CSize
    -> Ptr CUChar -> CSize -> IO CInt

-- | size_t EVP_HPKE_CTX_max_overhead(const EVP_HPKE_CTX *ctx)
foreign import ccall unsafe "EVP_HPKE_CTX_max_overhead"
  c_EVP_HPKE_CTX_max_overhead :: Ptr EVP_HPKE_CTX -> IO CSize

-- Query

-- | size_t EVP_HPKE_KEM_public_key_len(const EVP_HPKE_KEM *kem)
foreign import ccall unsafe "EVP_HPKE_KEM_public_key_len"
  c_EVP_HPKE_KEM_public_key_len :: Ptr EVP_HPKE_KEM -> CSize

-- | size_t EVP_HPKE_KEM_private_key_len(const EVP_HPKE_KEM *kem)
foreign import ccall unsafe "EVP_HPKE_KEM_private_key_len"
  c_EVP_HPKE_KEM_private_key_len :: Ptr EVP_HPKE_KEM -> CSize

-- | size_t EVP_HPKE_KEM_enc_len(const EVP_HPKE_KEM *kem)
foreign import ccall unsafe "EVP_HPKE_KEM_enc_len"
  c_EVP_HPKE_KEM_enc_len :: Ptr EVP_HPKE_KEM -> CSize
