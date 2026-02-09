{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.ECDH
  ( c_ECDH_compute_key_fips
  ) where

import Crypto.BoringSSL.Internal.FFI.ECKey (EC_KEY, EC_POINT)
import Foreign.C.Types
import Foreign.Ptr

-- | int ECDH_compute_key_fips(uint8_t *out, size_t out_len,
--                             const EC_POINT *pub_key, const EC_KEY *priv_key)
foreign import ccall unsafe "ECDH_compute_key_fips"
  c_ECDH_compute_key_fips :: Ptr CUChar -> CSize -> Ptr EC_POINT -> Ptr EC_KEY -> IO CInt
