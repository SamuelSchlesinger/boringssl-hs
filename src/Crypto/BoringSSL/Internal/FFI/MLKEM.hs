{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.MLKEM
  ( -- * Opaque struct types
    MLKEM768_private_key
  , MLKEM768_public_key
  , MLKEM1024_private_key
  , MLKEM1024_public_key
    -- * Constants
  , mlkem768PublicKeyBytes
  , mlkem768CiphertextBytes
  , mlkem1024PublicKeyBytes
  , mlkem1024CiphertextBytes
  , mlkemSharedSecretBytes
  , mlkemSeedBytes
  , mlkem768PrivateKeySize
  , mlkem768PublicKeySize
  , mlkem1024PrivateKeySize
  , mlkem1024PublicKeySize
    -- * ML-KEM-768
  , c_MLKEM768_generate_key
  , c_MLKEM768_encap
  , c_MLKEM768_decap
  , c_MLKEM768_public_from_private
  , c_MLKEM768_parse_public_key
    -- * ML-KEM-1024
  , c_MLKEM1024_generate_key
  , c_MLKEM1024_encap
  , c_MLKEM1024_decap
  , c_MLKEM1024_public_from_private
  , c_MLKEM1024_parse_public_key
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque struct types (must not leave address space)
data MLKEM768_private_key
data MLKEM768_public_key
data MLKEM1024_private_key
data MLKEM1024_public_key

-- Constants from mlkem.h
-- MLKEM768_PUBLIC_KEY_BYTES = 1184
mlkem768PublicKeyBytes :: Int
mlkem768PublicKeyBytes = 1184

-- MLKEM768_CIPHERTEXT_BYTES = 1088
mlkem768CiphertextBytes :: Int
mlkem768CiphertextBytes = 1088

-- MLKEM1024_PUBLIC_KEY_BYTES = 1568
mlkem1024PublicKeyBytes :: Int
mlkem1024PublicKeyBytes = 1568

-- MLKEM1024_CIPHERTEXT_BYTES = 1568
mlkem1024CiphertextBytes :: Int
mlkem1024CiphertextBytes = 1568

-- MLKEM_SHARED_SECRET_BYTES = 32
mlkemSharedSecretBytes :: Int
mlkemSharedSecretBytes = 32

-- MLKEM_SEED_BYTES = 64
mlkemSeedBytes :: Int
mlkemSeedBytes = 64

-- Struct sizes computed from the header:
-- MLKEM768_private_key: union { uint8_t bytes[512*(3+3+9)+32+32+32]; ... }
--   = 512*15 + 96 = 7680 + 96 = 7776 bytes
mlkem768PrivateKeySize :: Int
mlkem768PrivateKeySize = 7776

-- MLKEM768_public_key: union { uint8_t bytes[512*(3+9)+32+32]; ... }
--   = 512*12 + 64 = 6144 + 64 = 6208 bytes
mlkem768PublicKeySize :: Int
mlkem768PublicKeySize = 6208

-- MLKEM1024_private_key: union { uint8_t bytes[512*(4+4+16)+32+32+32]; ... }
--   = 512*24 + 96 = 12288 + 96 = 12384 bytes
mlkem1024PrivateKeySize :: Int
mlkem1024PrivateKeySize = 12384

-- MLKEM1024_public_key: union { uint8_t bytes[512*(4+16)+32+32]; ... }
--   = 512*20 + 64 = 10240 + 64 = 10304 bytes
mlkem1024PublicKeySize :: Int
mlkem1024PublicKeySize = 10304


-- ML-KEM-768 FFI

-- | void MLKEM768_generate_key(
--     uint8_t out_encoded_public_key[1184],
--     uint8_t optional_out_seed[64],
--     struct MLKEM768_private_key *out_private_key)
foreign import ccall safe "MLKEM768_generate_key"
  c_MLKEM768_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- optional_out_seed (can be nullPtr)
    -> Ptr MLKEM768_private_key      -- out_private_key
    -> IO ()

-- | void MLKEM768_public_from_private(
--     struct MLKEM768_public_key *out_public_key,
--     const struct MLKEM768_private_key *private_key)
foreign import ccall safe "MLKEM768_public_from_private"
  c_MLKEM768_public_from_private
    :: Ptr MLKEM768_public_key       -- out_public_key
    -> Ptr MLKEM768_private_key      -- private_key
    -> IO ()

-- | void MLKEM768_encap(
--     uint8_t out_ciphertext[1088],
--     uint8_t out_shared_secret[32],
--     const struct MLKEM768_public_key *public_key)
foreign import ccall safe "MLKEM768_encap"
  c_MLKEM768_encap
    :: Ptr CUChar                    -- out_ciphertext
    -> Ptr CUChar                    -- out_shared_secret
    -> Ptr MLKEM768_public_key       -- public_key
    -> IO ()

-- | int MLKEM768_decap(
--     uint8_t out_shared_secret[32],
--     const uint8_t *ciphertext, size_t ciphertext_len,
--     const struct MLKEM768_private_key *private_key)
foreign import ccall safe "MLKEM768_decap"
  c_MLKEM768_decap
    :: Ptr CUChar                    -- out_shared_secret
    -> Ptr CUChar                    -- ciphertext
    -> CSize                         -- ciphertext_len
    -> Ptr MLKEM768_private_key      -- private_key
    -> IO CInt


-- | int MLKEM768_parse_public_key(
--     struct MLKEM768_public_key *public_key, CBS *cbs)
foreign import ccall unsafe "MLKEM768_parse_public_key"
  c_MLKEM768_parse_public_key
    :: Ptr MLKEM768_public_key       -- out_public_key
    -> Ptr ()                        -- CBS *cbs
    -> IO CInt

-- ML-KEM-1024 FFI

-- | void MLKEM1024_generate_key(
--     uint8_t out_encoded_public_key[1568],
--     uint8_t optional_out_seed[64],
--     struct MLKEM1024_private_key *out_private_key)
foreign import ccall safe "MLKEM1024_generate_key"
  c_MLKEM1024_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- optional_out_seed (can be nullPtr)
    -> Ptr MLKEM1024_private_key     -- out_private_key
    -> IO ()

-- | void MLKEM1024_public_from_private(
--     struct MLKEM1024_public_key *out_public_key,
--     const struct MLKEM1024_private_key *private_key)
foreign import ccall safe "MLKEM1024_public_from_private"
  c_MLKEM1024_public_from_private
    :: Ptr MLKEM1024_public_key      -- out_public_key
    -> Ptr MLKEM1024_private_key     -- private_key
    -> IO ()

-- | void MLKEM1024_encap(
--     uint8_t out_ciphertext[1568],
--     uint8_t out_shared_secret[32],
--     const struct MLKEM1024_public_key *public_key)
foreign import ccall safe "MLKEM1024_encap"
  c_MLKEM1024_encap
    :: Ptr CUChar                    -- out_ciphertext
    -> Ptr CUChar                    -- out_shared_secret
    -> Ptr MLKEM1024_public_key      -- public_key
    -> IO ()

-- | int MLKEM1024_parse_public_key(
--     struct MLKEM1024_public_key *public_key, CBS *cbs)
foreign import ccall unsafe "MLKEM1024_parse_public_key"
  c_MLKEM1024_parse_public_key
    :: Ptr MLKEM1024_public_key      -- out_public_key
    -> Ptr ()                        -- CBS *cbs
    -> IO CInt

-- | int MLKEM1024_decap(
--     uint8_t out_shared_secret[32],
--     const uint8_t *ciphertext, size_t ciphertext_len,
--     const struct MLKEM1024_private_key *private_key)
foreign import ccall safe "MLKEM1024_decap"
  c_MLKEM1024_decap
    :: Ptr CUChar                    -- out_shared_secret
    -> Ptr CUChar                    -- ciphertext
    -> CSize                         -- ciphertext_len
    -> Ptr MLKEM1024_private_key     -- private_key
    -> IO CInt
