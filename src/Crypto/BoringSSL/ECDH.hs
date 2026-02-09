module Crypto.BoringSSL.ECDH
  ( ECCurve(..)
  , ECKeyPair
  , ECPublicKey
  , ecPublicKeyOfPair
  , generateECKeyPair
  , ecdhComputeSecret
    -- * Key serialization
  , ecPublicKeyBytes
  , ecPrivateKeyBytes
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr

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
      fptr <- BSI.mallocByteString outLen
      rc <- withForeignPtr fptr $ \ptr ->
        c_ECDH_compute_key_fips (castPtr ptr) (fromIntegral outLen) peerPoint myKeyPtr
      if rc /= 1
        then do
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "ecdhComputeSecret: ECDH_compute_key_fips failed") id merr))
        else
          return (Right (BSI.BS fptr outLen))
