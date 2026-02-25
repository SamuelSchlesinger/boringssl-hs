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
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Foreign.Ptr

import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.ECKey
import Crypto.BoringSSL.Internal.FFI.ECDH
import Crypto.BoringSSL.Internal.SecureBytes

-- | Compute a shared secret using ECDH (FIPS-compliant variant).
-- The output is a hash of the shared point x-coordinate. The output
-- length determines which hash is used internally:
-- 32 -> SHA-256, 48 -> SHA-384, 64 -> SHA-512.
ecdhComputeSecret :: ECKeyPair -> ECPublicKey -> Int -> IO (Either CryptoError SecureBytes)
ecdhComputeSecret myKey peerPub outLen
  | outLen `notElem` [32, 48, 64] =
      return (Left (InvalidInput "ecdhComputeSecret: output length must be 32, 48, or 64"))
  | otherwise = withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> runExceptT $ do
      peerPoint <- liftIO $ c_EC_KEY_get0_public_key peerKeyPtr
      liftIO clearBoringSSLError
      ssSB <- liftIO $ createSecureBytes outLen $ \_ -> return ()
      rc <- liftIO $ withSecureBytes ssSB $ \ptr _ ->
        c_ECDH_compute_key_fips (castPtr ptr) (fromIntegral outLen) peerPoint myKeyPtr
      checkRCError rc "ecdhComputeSecret: ECDH_compute_key_fips failed"
      return ssSB

-- | Compute a raw ECDH shared secret (x-coordinate of shared point).
-- Returns the x-coordinate of privKey * peerPubKey, zero-padded to the
-- field size: 32 bytes for P-256, 48 for P-384, 66 for P-521.
ecdhComputeRawSecret :: ECKeyPair -> ECPublicKey -> IO (Either CryptoError SecureBytes)
ecdhComputeRawSecret myKey peerPub = withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> runExceptT $ do
      groupPtr <- liftIO (c_EC_KEY_get0_group myKeyPtr)
        >>= \p -> nonNull p (OperationFailed "ecdhComputeRawSecret: EC_KEY_get0_group returned NULL")
      degree <- liftIO $ c_EC_GROUP_get_degree groupPtr
      let fieldBytes = fromIntegral ((degree + 7) `div` 8) :: Int
      privBn <- liftIO (c_EC_KEY_get0_private_key myKeyPtr)
        >>= \p -> nonNull p (OperationFailed "ecdhComputeRawSecret: no private key")
      peerPoint <- liftIO (c_EC_KEY_get0_public_key peerKeyPtr)
        >>= \p -> nonNull p (OperationFailed "ecdhComputeRawSecret: no peer public key")
      sharedPt <- liftIO (c_EC_POINT_new groupPtr)
        >>= \p -> nonNull p (AllocationFailure "ecdhComputeRawSecret: EC_POINT_new failed")
      flip finallyE (c_EC_POINT_free sharedPt) $ do
        liftIO clearBoringSSLError
        rc <- liftIO $ c_EC_POINT_mul groupPtr sharedPt nullPtr peerPoint privBn nullPtr
        checkRCError rc "ecdhComputeRawSecret: EC_POINT_mul failed"
        xBn <- liftIO c_BN_new
          >>= \p -> nonNull p (AllocationFailure "ecdhComputeRawSecret: BN_new failed")
        flip finallyE (c_BN_clear_free xBn) $ do
          rc2 <- liftIO $ c_EC_POINT_get_affine_coordinates_GFp groupPtr sharedPt xBn nullPtr nullPtr
          checkRCError rc2 "ecdhComputeRawSecret: get_affine_coordinates failed"
          ssSB <- liftIO $ createSecureBytes fieldBytes $ \_ -> return ()
          rc3 <- liftIO $ withSecureBytes ssSB $ \ptr _ ->
            c_BN_bn2bin_padded (castPtr ptr) (fromIntegral fieldBytes) xBn
          checkRC rc3 (OperationFailed "ecdhComputeRawSecret: BN_bn2bin_padded failed")
          return ssSB
