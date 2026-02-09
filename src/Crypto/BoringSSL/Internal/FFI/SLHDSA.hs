{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.SLHDSA
  ( -- * Constants
    slhdsaSha2128sPublicKeyBytes
  , slhdsaSha2128sPrivateKeyBytes
  , slhdsaSha2128sSignatureBytes
  , slhdsaShake256fPublicKeyBytes
  , slhdsaShake256fPrivateKeyBytes
  , slhdsaShake256fSignatureBytes
    -- * SLH-DSA-SHA2-128s
  , c_SLHDSA_SHA2_128S_generate_key
  , c_SLHDSA_SHA2_128S_public_from_private
  , c_SLHDSA_SHA2_128S_sign
  , c_SLHDSA_SHA2_128S_verify
    -- * SLH-DSA-SHAKE-256f
  , c_SLHDSA_SHAKE_256F_generate_key
  , c_SLHDSA_SHAKE_256F_public_from_private
  , c_SLHDSA_SHAKE_256F_sign
  , c_SLHDSA_SHAKE_256F_verify
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Constants

slhdsaSha2128sPublicKeyBytes :: Int
slhdsaSha2128sPublicKeyBytes = 32

slhdsaSha2128sPrivateKeyBytes :: Int
slhdsaSha2128sPrivateKeyBytes = 64

slhdsaSha2128sSignatureBytes :: Int
slhdsaSha2128sSignatureBytes = 7856

slhdsaShake256fPublicKeyBytes :: Int
slhdsaShake256fPublicKeyBytes = 64

slhdsaShake256fPrivateKeyBytes :: Int
slhdsaShake256fPrivateKeyBytes = 128

slhdsaShake256fSignatureBytes :: Int
slhdsaShake256fSignatureBytes = 49856

-- SLH-DSA-SHA2-128s

-- | void SLHDSA_SHA2_128S_generate_key(uint8_t out_public_key[32],
--                                       uint8_t out_private_key[64])
foreign import ccall safe "SLHDSA_SHA2_128S_generate_key"
  c_SLHDSA_SHA2_128S_generate_key :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | void SLHDSA_SHA2_128S_public_from_private(uint8_t out_public_key[32],
--                                              const uint8_t private_key[64])
foreign import ccall unsafe "SLHDSA_SHA2_128S_public_from_private"
  c_SLHDSA_SHA2_128S_public_from_private :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | int SLHDSA_SHA2_128S_sign(uint8_t out_signature[7856],
--                              const uint8_t private_key[64],
--                              const uint8_t *msg, size_t msg_len,
--                              const uint8_t *context, size_t context_len)
foreign import ccall safe "SLHDSA_SHA2_128S_sign"
  c_SLHDSA_SHA2_128S_sign :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> CSize
                          -> Ptr CUChar -> CSize -> IO CInt

-- | int SLHDSA_SHA2_128S_verify(const uint8_t *signature, size_t signature_len,
--                                const uint8_t public_key[32],
--                                const uint8_t *msg, size_t msg_len,
--                                const uint8_t *context, size_t context_len)
foreign import ccall safe "SLHDSA_SHA2_128S_verify"
  c_SLHDSA_SHA2_128S_verify :: Ptr CUChar -> CSize -> Ptr CUChar
                            -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize
                            -> IO CInt

-- SLH-DSA-SHAKE-256f

-- | void SLHDSA_SHAKE_256F_generate_key(uint8_t out_public_key[64],
--                                        uint8_t out_private_key[128])
foreign import ccall safe "SLHDSA_SHAKE_256F_generate_key"
  c_SLHDSA_SHAKE_256F_generate_key :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | void SLHDSA_SHAKE_256F_public_from_private(uint8_t out_public_key[64],
--                                               const uint8_t private_key[128])
foreign import ccall unsafe "SLHDSA_SHAKE_256F_public_from_private"
  c_SLHDSA_SHAKE_256F_public_from_private :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | int SLHDSA_SHAKE_256F_sign(uint8_t out_signature[49856],
--                               const uint8_t private_key[128],
--                               const uint8_t *msg, size_t msg_len,
--                               const uint8_t *context, size_t context_len)
foreign import ccall safe "SLHDSA_SHAKE_256F_sign"
  c_SLHDSA_SHAKE_256F_sign :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> CSize
                           -> Ptr CUChar -> CSize -> IO CInt

-- | int SLHDSA_SHAKE_256F_verify(const uint8_t *signature, size_t signature_len,
--                                 const uint8_t public_key[64],
--                                 const uint8_t *msg, size_t msg_len,
--                                 const uint8_t *context, size_t context_len)
foreign import ccall safe "SLHDSA_SHAKE_256F_verify"
  c_SLHDSA_SHAKE_256F_verify :: Ptr CUChar -> CSize -> Ptr CUChar
                             -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize
                             -> IO CInt
