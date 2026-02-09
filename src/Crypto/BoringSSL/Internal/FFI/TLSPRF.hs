{-# LANGUAGE CApiFFI #-}
module Crypto.BoringSSL.Internal.FFI.TLSPRF
  ( c_CRYPTO_tls1_prf
  ) where

import Crypto.BoringSSL.Internal.FFI.Digest (EVP_MD)
import Foreign.C.Types
import Foreign.Ptr

-- | int CRYPTO_tls1_prf(const EVP_MD *digest, uint8_t *out, size_t out_len,
--                        const uint8_t *secret, size_t secret_len,
--                        const uint8_t *label, size_t label_len,
--                        const uint8_t *seed1, size_t seed1_len,
--                        const uint8_t *seed2, size_t seed2_len)
foreign import capi unsafe "openssl/tls_prf.h CRYPTO_tls1_prf"
  c_CRYPTO_tls1_prf :: Ptr EVP_MD
                    -> Ptr CUChar -> CSize
                    -> Ptr CUChar -> CSize
                    -> Ptr CUChar -> CSize
                    -> Ptr CUChar -> CSize
                    -> Ptr CUChar -> CSize
                    -> IO CInt
