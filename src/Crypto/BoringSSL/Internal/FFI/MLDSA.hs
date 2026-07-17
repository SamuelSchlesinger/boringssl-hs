{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.MLDSA
  ( -- * Opaque struct types
    MLDSA44_private_key
  , MLDSA44_public_key
  , MLDSA65_private_key
  , MLDSA65_public_key
  , MLDSA87_private_key
  , MLDSA87_public_key
    -- * Constants
  , mldsaSeedBytes
  , mldsa44PublicKeyBytes
  , mldsa44SignatureBytes
  , mldsa44PrivateKeySize
  , mldsa44PublicKeySize
  , mldsa65PublicKeyBytes
  , mldsa65SignatureBytes
  , mldsa65PrivateKeySize
  , mldsa65PublicKeySize
  , mldsa87PublicKeyBytes
  , mldsa87SignatureBytes
  , mldsa87PrivateKeySize
  , mldsa87PublicKeySize
    -- * ML-DSA-44 FFI
  , c_MLDSA44_generate_key
  , c_MLDSA44_private_key_from_seed
  , c_MLDSA44_public_from_private
  , c_MLDSA44_sign
  , c_MLDSA44_verify
  , c_MLDSA44_parse_public_key
  , c_MLDSA44_marshal_public_key
    -- * ML-DSA-65 FFI
  , c_MLDSA65_generate_key
  , c_MLDSA65_private_key_from_seed
  , c_MLDSA65_public_from_private
  , c_MLDSA65_sign
  , c_MLDSA65_verify
  , c_MLDSA65_parse_public_key
  , c_MLDSA65_marshal_public_key
    -- * ML-DSA-87 FFI
  , c_MLDSA87_generate_key
  , c_MLDSA87_private_key_from_seed
  , c_MLDSA87_public_from_private
  , c_MLDSA87_sign
  , c_MLDSA87_verify
  , c_MLDSA87_parse_public_key
  , c_MLDSA87_marshal_public_key
  ) where

import Foreign.C.Types
import Foreign.Ptr

import Crypto.BoringSSL.Internal.FFI.Constants

-- Opaque struct types (must not leave address space)
data MLDSA44_private_key
data MLDSA44_public_key
data MLDSA65_private_key
data MLDSA65_public_key
data MLDSA87_private_key
data MLDSA87_public_key

-- | MLDSA_SEED_BYTES = 32
mldsaSeedBytes :: Int
mldsaSeedBytes = 32

-- ML-DSA-44 constants from mldsa.h

-- | MLDSA44_PUBLIC_KEY_BYTES = 1312
mldsa44PublicKeyBytes :: Int
mldsa44PublicKeyBytes = 1312

-- | MLDSA44_SIGNATURE_BYTES = 2420
mldsa44SignatureBytes :: Int
mldsa44SignatureBytes = 2420

-- Struct sizes derived from BoringSSL headers at compile time.
mldsa44PrivateKeySize :: Int
mldsa44PrivateKeySize = sizeofMLDSA44PrivateKey

mldsa44PublicKeySize :: Int
mldsa44PublicKeySize = sizeofMLDSA44PublicKey

-- ML-DSA-65 constants from mldsa.h

-- | MLDSA65_PUBLIC_KEY_BYTES = 1952
mldsa65PublicKeyBytes :: Int
mldsa65PublicKeyBytes = 1952

-- | MLDSA65_SIGNATURE_BYTES = 3309
mldsa65SignatureBytes :: Int
mldsa65SignatureBytes = 3309

mldsa65PrivateKeySize :: Int
mldsa65PrivateKeySize = sizeofMLDSA65PrivateKey

mldsa65PublicKeySize :: Int
mldsa65PublicKeySize = sizeofMLDSA65PublicKey

-- ML-DSA-87 constants from mldsa.h

-- | MLDSA87_PUBLIC_KEY_BYTES = 2592
mldsa87PublicKeyBytes :: Int
mldsa87PublicKeyBytes = 2592

-- | MLDSA87_SIGNATURE_BYTES = 4627
mldsa87SignatureBytes :: Int
mldsa87SignatureBytes = 4627

mldsa87PrivateKeySize :: Int
mldsa87PrivateKeySize = sizeofMLDSA87PrivateKey

mldsa87PublicKeySize :: Int
mldsa87PublicKeySize = sizeofMLDSA87PublicKey


-- ML-DSA-44 FFI

-- | int MLDSA44_generate_key(
--     uint8_t out_encoded_public_key[1312],
--     uint8_t out_seed[32],
--     struct MLDSA44_private_key *out_private_key)
foreign import capi safe "openssl/mldsa.h MLDSA44_generate_key"
  c_MLDSA44_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- out_seed
    -> Ptr MLDSA44_private_key       -- out_private_key
    -> IO CInt

-- | int MLDSA44_private_key_from_seed(
--     struct MLDSA44_private_key *out_private_key,
--     const uint8_t *seed, size_t seed_len)
foreign import capi safe "openssl/mldsa.h MLDSA44_private_key_from_seed"
  c_MLDSA44_private_key_from_seed
    :: Ptr MLDSA44_private_key       -- out_private_key
    -> Ptr CUChar                    -- seed
    -> CSize                         -- seed_len
    -> IO CInt

-- | int MLDSA44_public_from_private(
--     struct MLDSA44_public_key *out_public_key,
--     const struct MLDSA44_private_key *private_key)
foreign import capi safe "openssl/mldsa.h MLDSA44_public_from_private"
  c_MLDSA44_public_from_private
    :: Ptr MLDSA44_public_key        -- out_public_key
    -> Ptr MLDSA44_private_key       -- private_key
    -> IO CInt

-- | int MLDSA44_sign(
--     uint8_t out_encoded_signature[2420],
--     const struct MLDSA44_private_key *private_key,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import capi safe "openssl/mldsa.h MLDSA44_sign"
  c_MLDSA44_sign
    :: Ptr CUChar                    -- out_encoded_signature
    -> Ptr MLDSA44_private_key       -- private_key
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA44_verify(
--     const struct MLDSA44_public_key *public_key,
--     const uint8_t *signature, size_t signature_len,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import capi safe "openssl/mldsa.h MLDSA44_verify"
  c_MLDSA44_verify
    :: Ptr MLDSA44_public_key        -- public_key
    -> Ptr CUChar                    -- signature
    -> CSize                         -- signature_len
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA44_parse_public_key(
--     struct MLDSA44_public_key *public_key, CBS *in)
foreign import capi unsafe "openssl/mldsa.h MLDSA44_parse_public_key"
  c_MLDSA44_parse_public_key
    :: Ptr MLDSA44_public_key        -- out_public_key
    -> Ptr ()                        -- CBS *in
    -> IO CInt

-- | int MLDSA44_marshal_public_key(
--     CBB *out, const struct MLDSA44_public_key *public_key)
foreign import capi unsafe "openssl/mldsa.h MLDSA44_marshal_public_key"
  c_MLDSA44_marshal_public_key
    :: Ptr ()                        -- CBB *out
    -> Ptr MLDSA44_public_key        -- public_key
    -> IO CInt


-- ML-DSA-65 FFI

-- | int MLDSA65_generate_key(
--     uint8_t out_encoded_public_key[1952],
--     uint8_t out_seed[32],
--     struct MLDSA65_private_key *out_private_key)
foreign import capi safe "openssl/mldsa.h MLDSA65_generate_key"
  c_MLDSA65_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- out_seed
    -> Ptr MLDSA65_private_key       -- out_private_key
    -> IO CInt

-- | int MLDSA65_private_key_from_seed(
--     struct MLDSA65_private_key *out_private_key,
--     const uint8_t *seed, size_t seed_len)
foreign import capi safe "openssl/mldsa.h MLDSA65_private_key_from_seed"
  c_MLDSA65_private_key_from_seed
    :: Ptr MLDSA65_private_key       -- out_private_key
    -> Ptr CUChar                    -- seed
    -> CSize                         -- seed_len
    -> IO CInt

-- | int MLDSA65_public_from_private(
--     struct MLDSA65_public_key *out_public_key,
--     const struct MLDSA65_private_key *private_key)
foreign import capi safe "openssl/mldsa.h MLDSA65_public_from_private"
  c_MLDSA65_public_from_private
    :: Ptr MLDSA65_public_key        -- out_public_key
    -> Ptr MLDSA65_private_key       -- private_key
    -> IO CInt

-- | int MLDSA65_sign(
--     uint8_t out_encoded_signature[3309],
--     const struct MLDSA65_private_key *private_key,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import capi safe "openssl/mldsa.h MLDSA65_sign"
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
foreign import capi safe "openssl/mldsa.h MLDSA65_verify"
  c_MLDSA65_verify
    :: Ptr MLDSA65_public_key        -- public_key
    -> Ptr CUChar                    -- signature
    -> CSize                         -- signature_len
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA65_parse_public_key(
--     struct MLDSA65_public_key *public_key, CBS *in)
foreign import capi unsafe "openssl/mldsa.h MLDSA65_parse_public_key"
  c_MLDSA65_parse_public_key
    :: Ptr MLDSA65_public_key        -- out_public_key
    -> Ptr ()                        -- CBS *in
    -> IO CInt

-- | int MLDSA65_marshal_public_key(
--     CBB *out, const struct MLDSA65_public_key *public_key)
foreign import capi unsafe "openssl/mldsa.h MLDSA65_marshal_public_key"
  c_MLDSA65_marshal_public_key
    :: Ptr ()                        -- CBB *out
    -> Ptr MLDSA65_public_key        -- public_key
    -> IO CInt


-- ML-DSA-87 FFI

-- | int MLDSA87_generate_key(
--     uint8_t out_encoded_public_key[2592],
--     uint8_t out_seed[32],
--     struct MLDSA87_private_key *out_private_key)
foreign import capi safe "openssl/mldsa.h MLDSA87_generate_key"
  c_MLDSA87_generate_key
    :: Ptr CUChar                    -- out_encoded_public_key
    -> Ptr CUChar                    -- out_seed
    -> Ptr MLDSA87_private_key       -- out_private_key
    -> IO CInt

-- | int MLDSA87_private_key_from_seed(
--     struct MLDSA87_private_key *out_private_key,
--     const uint8_t *seed, size_t seed_len)
foreign import capi safe "openssl/mldsa.h MLDSA87_private_key_from_seed"
  c_MLDSA87_private_key_from_seed
    :: Ptr MLDSA87_private_key       -- out_private_key
    -> Ptr CUChar                    -- seed
    -> CSize                         -- seed_len
    -> IO CInt

-- | int MLDSA87_public_from_private(
--     struct MLDSA87_public_key *out_public_key,
--     const struct MLDSA87_private_key *private_key)
foreign import capi safe "openssl/mldsa.h MLDSA87_public_from_private"
  c_MLDSA87_public_from_private
    :: Ptr MLDSA87_public_key        -- out_public_key
    -> Ptr MLDSA87_private_key       -- private_key
    -> IO CInt

-- | int MLDSA87_sign(
--     uint8_t out_encoded_signature[4627],
--     const struct MLDSA87_private_key *private_key,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import capi safe "openssl/mldsa.h MLDSA87_sign"
  c_MLDSA87_sign
    :: Ptr CUChar                    -- out_encoded_signature
    -> Ptr MLDSA87_private_key       -- private_key
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA87_verify(
--     const struct MLDSA87_public_key *public_key,
--     const uint8_t *signature, size_t signature_len,
--     const uint8_t *msg, size_t msg_len,
--     const uint8_t *context, size_t context_len)
foreign import capi safe "openssl/mldsa.h MLDSA87_verify"
  c_MLDSA87_verify
    :: Ptr MLDSA87_public_key        -- public_key
    -> Ptr CUChar                    -- signature
    -> CSize                         -- signature_len
    -> Ptr CUChar                    -- msg
    -> CSize                         -- msg_len
    -> Ptr CUChar                    -- context
    -> CSize                         -- context_len
    -> IO CInt

-- | int MLDSA87_parse_public_key(
--     struct MLDSA87_public_key *public_key, CBS *in)
foreign import capi unsafe "openssl/mldsa.h MLDSA87_parse_public_key"
  c_MLDSA87_parse_public_key
    :: Ptr MLDSA87_public_key        -- out_public_key
    -> Ptr ()                        -- CBS *in
    -> IO CInt

-- | int MLDSA87_marshal_public_key(
--     CBB *out, const struct MLDSA87_public_key *public_key)
foreign import capi unsafe "openssl/mldsa.h MLDSA87_marshal_public_key"
  c_MLDSA87_marshal_public_key
    :: Ptr ()                        -- CBB *out
    -> Ptr MLDSA87_public_key        -- public_key
    -> IO CInt
