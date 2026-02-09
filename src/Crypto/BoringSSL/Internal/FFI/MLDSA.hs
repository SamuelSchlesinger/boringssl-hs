{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.MLDSA
  ( -- * Opaque struct types
    MLDSA65_private_key
  , MLDSA65_public_key
    -- * Constants
  , mldsa65PublicKeyBytes
  , mldsa65SignatureBytes
  , mldsaSeedBytes
  , mldsa65PrivateKeySize
  , mldsa65PublicKeySize
    -- * ML-DSA-65 FFI
  , c_MLDSA65_generate_key
  , c_MLDSA65_sign
  , c_MLDSA65_verify
  , c_MLDSA65_public_from_private
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque struct types
data MLDSA65_private_key
data MLDSA65_public_key

-- Constants from mldsa.h
-- MLDSA65_PUBLIC_KEY_BYTES = 1952
mldsa65PublicKeyBytes :: Int
mldsa65PublicKeyBytes = 1952

-- MLDSA65_SIGNATURE_BYTES = 3309
mldsa65SignatureBytes :: Int
mldsa65SignatureBytes = 3309

-- MLDSA_SEED_BYTES = 32
mldsaSeedBytes :: Int
mldsaSeedBytes = 32

-- Struct sizes computed from the header:
-- MLDSA65_private_key: union { uint8_t bytes[(32+64+256*4*6)+32+256*4*(5+6+6)]; ... }
--   = (32+64+6144) + 32 + 256*4*17 = 6240 + 32 + 17408 = 23680 bytes
mldsa65PrivateKeySize :: Int
mldsa65PrivateKeySize = 23680

-- MLDSA65_public_key: union { uint8_t bytes[32+64+256*4*6]; ... }
--   = 32 + 64 + 6144 = 6240 bytes
mldsa65PublicKeySize :: Int
mldsa65PublicKeySize = 6240


-- ML-DSA-65 FFI

-- | int MLDSA65_generate_key(
--     uint8_t out_encoded_public_key[1952],
--     uint8_t out_seed[32],
--     struct MLDSA65_private_key *out_private_key)
foreign import ccall unsafe "MLDSA65_generate_key"
  c_MLDSA65_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- out_seed
    -> Ptr MLDSA65_private_key       -- out_private_key
    -> IO CInt

-- | int MLDSA65_public_from_private(
--     struct MLDSA65_public_key *out_public_key,
--     const struct MLDSA65_private_key *private_key)
foreign import ccall unsafe "MLDSA65_public_from_private"
  c_MLDSA65_public_from_private
    :: Ptr MLDSA65_public_key        -- out_public_key
    -> Ptr MLDSA65_private_key       -- private_key
    -> IO CInt

-- | int MLDSA65_sign(
--     uint8_t out_encoded_signature[3309],
--     const struct MLDSA65_private_key *private_key,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import ccall unsafe "MLDSA65_sign"
  c_MLDSA65_sign
    :: Ptr CUChar                    -- out_encoded_signature
    -> Ptr MLDSA65_private_key       -- private_key
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA65_verify(
--     const struct MLDSA65_public_key *public_key,
--     const uint8_t *signature, size_t signature_len,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import ccall unsafe "MLDSA65_verify"
  c_MLDSA65_verify
    :: Ptr MLDSA65_public_key        -- public_key
    -> Ptr CUChar                    -- signature
    -> CSize                         -- signature_len
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt
