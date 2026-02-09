{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.ECDSA
  ( c_ECDSA_sign
  , c_ECDSA_verify
  , c_ECDSA_size
    -- * P1363 (fixed-size) signatures
  , c_ECDSA_sign_p1363
  , c_ECDSA_verify_p1363
  , c_ECDSA_size_p1363
  ) where

import Crypto.BoringSSL.Internal.FFI.ECKey (EC_KEY)
import Foreign.C.Types
import Foreign.Ptr

-- | int ECDSA_sign(int type, const uint8_t *digest, size_t digest_len,
--                  uint8_t *sig, unsigned int *sig_len, const EC_KEY *key)
foreign import capi safe "openssl/ecdsa.h ECDSA_sign"
  c_ECDSA_sign :: CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> Ptr CUInt -> Ptr EC_KEY -> IO CInt

-- | int ECDSA_verify(int type, const uint8_t *digest, size_t digest_len,
--                    const uint8_t *sig, size_t sig_len, const EC_KEY *key)
foreign import capi safe "openssl/ecdsa.h ECDSA_verify"
  c_ECDSA_verify :: CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr EC_KEY -> IO CInt

-- | size_t ECDSA_size(const EC_KEY *key)
foreign import capi unsafe "openssl/ecdsa.h ECDSA_size"
  c_ECDSA_size :: Ptr EC_KEY -> IO CSize

-- P1363 (fixed-size r||s) signatures

-- | int ECDSA_sign_p1363(const uint8_t *digest, size_t digest_len,
--                         uint8_t *sig, size_t *out_sig_len,
--                         size_t max_sig_len, const EC_KEY *key)
foreign import capi safe "openssl/ecdsa.h ECDSA_sign_p1363"
  c_ECDSA_sign_p1363 :: Ptr CUChar -> CSize -> Ptr CUChar -> Ptr CSize
                      -> CSize -> Ptr EC_KEY -> IO CInt

-- | int ECDSA_verify_p1363(const uint8_t *digest, size_t digest_len,
--                           const uint8_t *sig, size_t sig_len,
--                           const EC_KEY *key)
foreign import capi safe "openssl/ecdsa.h ECDSA_verify_p1363"
  c_ECDSA_verify_p1363 :: Ptr CUChar -> CSize -> Ptr CUChar -> CSize
                        -> Ptr EC_KEY -> IO CInt

-- | size_t ECDSA_size_p1363(const EC_KEY *key)
foreign import capi unsafe "openssl/ecdsa.h ECDSA_size_p1363"
  c_ECDSA_size_p1363 :: Ptr EC_KEY -> IO CSize
