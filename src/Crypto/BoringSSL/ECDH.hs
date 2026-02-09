module Crypto.BoringSSL.ECDH
  ( ECCurve(..)
  , ECKeyPair
  , ECPublicKey
  , ecPublicKeyOfPair
  , generateECKeyPair
  , ecdhComputeSecret
  ) where

import Data.ByteString (ByteString)
import Foreign.C.Types
import Foreign.Ptr

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.FFI.ECKey (c_EC_KEY_get0_public_key)
import Crypto.BoringSSL.Internal.FFI.ECDH

-- | Compute a shared secret using ECDH (FIPS-compliant variant).
-- The output is a hash of the shared point x-coordinate. The output
-- length determines which hash is used internally:
-- 32 -> SHA-256, 48 -> SHA-384, 64 -> SHA-512.
ecdhComputeSecret :: ECKeyPair -> ECPublicKey -> Int -> IO (Either BoringSSLError ByteString)
ecdhComputeSecret myKey peerPub outLen =
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> do
      peerPoint <- c_EC_KEY_get0_public_key peerKeyPtr
      bs <- createByteString outLen $ \outPtr -> do
        rc <- c_ECDH_compute_key_fips outPtr (fromIntegral outLen) peerPoint myKeyPtr
        if rc /= 1
          then fail "ecdhComputeSecret: ECDH_compute_key_fips failed"
          else return ()
      return (Right bs)
