{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Ed25519
  ( c_ED25519_keypair
  , c_ED25519_sign
  , c_ED25519_verify
  , c_ED25519_keypair_from_seed
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | void ED25519_keypair(uint8_t out_public_key[32], uint8_t out_private_key[64])
foreign import ccall unsafe "ED25519_keypair"
  c_ED25519_keypair :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | int ED25519_sign(uint8_t out_sig[64], const uint8_t *message,
--                    size_t message_len, const uint8_t private_key[64])
foreign import ccall safe "ED25519_sign"
  c_ED25519_sign :: Ptr CUChar -> Ptr CUChar -> CSize -> Ptr CUChar -> IO CInt

-- | int ED25519_verify(const uint8_t *message, size_t message_len,
--                      const uint8_t signature[64], const uint8_t public_key[32])
foreign import ccall safe "ED25519_verify"
  c_ED25519_verify :: Ptr CUChar -> CSize -> Ptr CUChar -> Ptr CUChar -> IO CInt

-- | void ED25519_keypair_from_seed(uint8_t out_public_key[32],
--                                  uint8_t out_private_key[64],
--                                  const uint8_t seed[32])
foreign import ccall unsafe "ED25519_keypair_from_seed"
  c_ED25519_keypair_from_seed :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> IO ()
