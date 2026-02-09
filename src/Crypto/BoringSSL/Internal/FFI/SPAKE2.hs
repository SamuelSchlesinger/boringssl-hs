{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.SPAKE2
  ( -- * Opaque types
    SPAKE2_CTX
    -- * Constants
  , spake2MaxMsgSize
  , spake2MaxKeySize
  , spake2RoleAlice
  , spake2RoleBob
    -- * Functions
  , c_SPAKE2_CTX_new
  , c_SPAKE2_CTX_free
  , c_SPAKE2_CTX_free_funptr
  , c_SPAKE2_generate_msg
  , c_SPAKE2_process_msg
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque type
data SPAKE2_CTX

-- Constants
spake2MaxMsgSize :: Int
spake2MaxMsgSize = 32

spake2MaxKeySize :: Int
spake2MaxKeySize = 64

-- enum spake2_role_t values
spake2RoleAlice :: CInt
spake2RoleAlice = 0

spake2RoleBob :: CInt
spake2RoleBob = 1

-- | SPAKE2_CTX *SPAKE2_CTX_new(
--     enum spake2_role_t my_role,
--     const uint8_t *my_name, size_t my_name_len,
--     const uint8_t *their_name, size_t their_name_len)
foreign import ccall unsafe "SPAKE2_CTX_new"
  c_SPAKE2_CTX_new :: CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize
                    -> IO (Ptr SPAKE2_CTX)

-- | void SPAKE2_CTX_free(SPAKE2_CTX *ctx)
foreign import ccall unsafe "SPAKE2_CTX_free"
  c_SPAKE2_CTX_free :: Ptr SPAKE2_CTX -> IO ()

-- | FunPtr for SPAKE2_CTX_free finalizer
foreign import ccall unsafe "&SPAKE2_CTX_free"
  c_SPAKE2_CTX_free_funptr :: FunPtr (Ptr SPAKE2_CTX -> IO ())

-- | int SPAKE2_generate_msg(SPAKE2_CTX *ctx, uint8_t *out,
--                           size_t *out_len, size_t max_out_len,
--                           const uint8_t *password, size_t password_len)
foreign import ccall unsafe "SPAKE2_generate_msg"
  c_SPAKE2_generate_msg :: Ptr SPAKE2_CTX -> Ptr CUChar -> Ptr CSize -> CSize
                         -> Ptr CUChar -> CSize -> IO CInt

-- | int SPAKE2_process_msg(SPAKE2_CTX *ctx, uint8_t *out_key,
--                          size_t *out_key_len, size_t max_out_key_len,
--                          const uint8_t *their_msg, size_t their_msg_len)
foreign import ccall unsafe "SPAKE2_process_msg"
  c_SPAKE2_process_msg :: Ptr SPAKE2_CTX -> Ptr CUChar -> Ptr CSize -> CSize
                        -> Ptr CUChar -> CSize -> IO CInt
