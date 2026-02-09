{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.X25519
  ( c_X25519_keypair
  , c_X25519
  , c_X25519_public_from_private
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | void X25519_keypair(uint8_t out_public_value[32], uint8_t out_private_key[32])
foreign import ccall unsafe "X25519_keypair"
  c_X25519_keypair :: Ptr CUChar -> Ptr CUChar -> IO ()

-- | int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
--              const uint8_t peer_public_value[32])
foreign import ccall unsafe "X25519"
  c_X25519 :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> IO CInt

-- | void X25519_public_from_private(uint8_t out_public_value[32],
--                                   const uint8_t private_key[32])
foreign import ccall unsafe "X25519_public_from_private"
  c_X25519_public_from_private :: Ptr CUChar -> Ptr CUChar -> IO ()
