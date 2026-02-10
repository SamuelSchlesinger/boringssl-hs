-- | Elliptic curve Diffie-Hellman key agreement.
--
-- Supports P-256 and P-384 curves using the FIPS-compliant
-- ECDH variant that hashes the shared point.
module Crypto.BoringSSL.ECDH
  ( -- * Key types
    ECCurve(..)
  , ECKeyPair
  , ECPublicKey
  , ecPublicKeyOfPair
    -- * Key generation
  , generateECKeyPair
    -- * Key agreement
  , ecdhComputeSecret
  , ecdhComputeRawSecret
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
import Control.Exception (finally)

import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.FFI.ECKey
import Crypto.BoringSSL.Internal.FFI.ECDH

-- | Compute a shared secret using ECDH (FIPS-compliant variant).
-- The output is a hash of the shared point x-coordinate. The output
-- length determines which hash is used internally:
-- 32 -> SHA-256, 48 -> SHA-384, 64 -> SHA-512.
ecdhComputeSecret :: ECKeyPair -> ECPublicKey -> Int -> IO (Either CryptoError ByteString)
ecdhComputeSecret myKey peerPub outLen
  | outLen `notElem` [32, 48, 64] =
      return (Left (InvalidInput "ecdhComputeSecret: output length must be 32, 48, or 64"))
  | otherwise = withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> do
      peerPoint <- c_EC_KEY_get0_public_key peerKeyPtr
      fptr <- BSI.mallocByteString outLen
      clearBoringSSLError
      rc <- withForeignPtr fptr $ \ptr ->
        c_ECDH_compute_key_fips (castPtr ptr) (fromIntegral outLen) peerPoint myKeyPtr
      if rc /= 1
        then do
          merr <- getBoringSSLError
          return (Left (maybe (OperationFailed "ecdhComputeSecret: ECDH_compute_key_fips failed") id merr))
        else
          return (Right (BSI.BS fptr outLen))

-- | Compute a raw ECDH shared secret (x-coordinate of shared point).
-- Returns the x-coordinate of privKey * peerPubKey, zero-padded to the
-- field size: 32 bytes for P-256, 48 for P-384, 66 for P-521.
ecdhComputeRawSecret :: ECKeyPair -> ECPublicKey -> IO (Either CryptoError ByteString)
ecdhComputeRawSecret myKey peerPub = withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> do
      groupPtr <- c_EC_KEY_get0_group myKeyPtr
      if groupPtr == nullPtr
        then return (Left (OperationFailed "ecdhComputeRawSecret: EC_KEY_get0_group returned NULL"))
        else do
          degree <- c_EC_GROUP_get_degree groupPtr
          let fieldBytes = fromIntegral ((degree + 7) `div` 8) :: Int
          privBn <- c_EC_KEY_get0_private_key myKeyPtr
          if privBn == nullPtr
            then return (Left (OperationFailed "ecdhComputeRawSecret: no private key"))
            else do
              peerPoint <- c_EC_KEY_get0_public_key peerKeyPtr
              if peerPoint == nullPtr
                then return (Left (OperationFailed "ecdhComputeRawSecret: no peer public key"))
                else do
                  sharedPt <- c_EC_POINT_new groupPtr
                  if sharedPt == nullPtr
                    then return (Left (AllocationFailure "ecdhComputeRawSecret: EC_POINT_new failed"))
                    else flip finally (c_EC_POINT_free sharedPt) $ do
                      -- shared = privBn * peerPoint
                      clearBoringSSLError
                      rc <- c_EC_POINT_mul groupPtr sharedPt nullPtr peerPoint privBn nullPtr
                      if rc /= 1
                        then do
                          merr <- getBoringSSLError
                          return (Left (maybe (OperationFailed "ecdhComputeRawSecret: EC_POINT_mul failed") id merr))
                        else do
                          xBn <- c_BN_new
                          if xBn == nullPtr
                            then return (Left (AllocationFailure "ecdhComputeRawSecret: BN_new failed"))
                            else flip finally (c_BN_clear_free xBn) $ do
                              rc2 <- c_EC_POINT_get_affine_coordinates_GFp groupPtr sharedPt xBn nullPtr nullPtr
                              if rc2 /= 1
                                then do
                                  merr <- getBoringSSLError
                                  return (Left (maybe (OperationFailed "ecdhComputeRawSecret: get_affine_coordinates failed") id merr))
                                else do
                                  fptr <- BSI.mallocByteString fieldBytes
                                  rc3 <- withForeignPtr fptr $ \ptr ->
                                    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral fieldBytes) xBn
                                  if rc3 /= 1
                                    then return (Left (OperationFailed "ecdhComputeRawSecret: BN_bn2bin_padded failed"))
                                    else return (Right (BSI.BS fptr fieldBytes))
