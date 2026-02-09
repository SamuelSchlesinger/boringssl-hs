{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.XWing
  ( -- * Opaque struct type
    XWING_private_key
    -- * Constants
  , xwingPublicKeyBytes
  , xwingPrivateKeyBytes
  , xwingCiphertextBytes
  , xwingSharedSecretBytes
  , xwingPrivateKeyStructSize
    -- * FFI bindings
  , c_XWING_generate_key
  , c_XWING_public_from_private
  , c_XWING_encap
  , c_XWING_decap
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | Opaque type representing @struct XWING_private_key@.
-- The contents must never leave the address space.
data XWING_private_key

-- Constants from xwing.h

-- | XWING_PUBLIC_KEY_BYTES = 1216
xwingPublicKeyBytes :: Int
xwingPublicKeyBytes = 1216

-- | XWING_PRIVATE_KEY_BYTES = 32 (encoded private key / seed)
xwingPrivateKeyBytes :: Int
xwingPrivateKeyBytes = 32

-- | XWING_CIPHERTEXT_BYTES = 1120
xwingCiphertextBytes :: Int
xwingCiphertextBytes = 1120

-- | XWING_SHARED_SECRET_BYTES = 32
xwingSharedSecretBytes :: Int
xwingSharedSecretBytes = 32

-- | sizeof(struct XWING_private_key)
-- Computed from: union { uint8_t bytes[512*(3+3+9)+32+32+32+32+32]; ... }
--   = 512*15 + 5*32 = 7680 + 160 = 7840 bytes
xwingPrivateKeyStructSize :: Int
xwingPrivateKeyStructSize = 7840


-- FFI bindings

-- | int XWING_generate_key(
--     uint8_t out_encoded_public_key[XWING_PUBLIC_KEY_BYTES],
--     struct XWING_private_key *out_private_key)
foreign import capi safe "openssl/xwing.h XWING_generate_key"
  c_XWING_generate_key
    :: Ptr CUChar              -- out_encoded_public_key
    -> Ptr XWING_private_key   -- out_private_key
    -> IO CInt

-- | int XWING_public_from_private(
--     uint8_t out_encoded_public_key[XWING_PUBLIC_KEY_BYTES],
--     const struct XWING_private_key *private_key)
foreign import capi safe "openssl/xwing.h XWING_public_from_private"
  c_XWING_public_from_private
    :: Ptr CUChar              -- out_encoded_public_key
    -> Ptr XWING_private_key   -- private_key (const)
    -> IO CInt

-- | int XWING_encap(
--     uint8_t out_ciphertext[XWING_CIPHERTEXT_BYTES],
--     uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
--     const uint8_t encoded_public_key[XWING_PUBLIC_KEY_BYTES])
foreign import capi safe "openssl/xwing.h XWING_encap"
  c_XWING_encap
    :: Ptr CUChar              -- out_ciphertext
    -> Ptr CUChar              -- out_shared_secret
    -> Ptr CUChar              -- encoded_public_key (const)
    -> IO CInt

-- | int XWING_decap(
--     uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
--     const uint8_t ciphertext[XWING_CIPHERTEXT_BYTES],
--     const struct XWING_private_key *private_key)
foreign import capi safe "openssl/xwing.h XWING_decap"
  c_XWING_decap
    :: Ptr CUChar              -- out_shared_secret
    -> Ptr CUChar              -- ciphertext (const)
    -> Ptr XWING_private_key   -- private_key (const)
    -> IO CInt
