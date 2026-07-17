-- | Elliptic curve Diffie-Hellman key agreement.
--
-- Supports P-256, P-384, and P-521 curves.
--
-- Two variants are provided:
--
-- * 'ecdhComputeSecret' — FIPS-compliant variant that hashes the shared
--   point's x-coordinate through SHA-256, SHA-384, or SHA-512 (selected by
--   output length). This is appropriate for most applications.
-- * 'ecdhComputeRawSecret' — returns the raw x-coordinate of the shared
--   point, zero-padded to the curve field size. Use this when you need to
--   feed the shared secret into your own KDF (e.g. HKDF).
--
-- __Cofactor and point validation:__ BoringSSL validates peer public keys
-- (rejecting the point at infinity and points not on the curve). For
-- prime-order curves (P-256, P-384, P-521) cofactor multiplication is not
-- needed since the cofactor is 1.
--
-- __Forward secrecy:__ Generate ephemeral key pairs per session with
-- 'generateECKeyPair' to achieve forward secrecy.
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
  , ecPrivateKeySecureBytes
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
  ) where

import Foreign.Ptr

import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.ECKey
import Crypto.BoringSSL.Internal.FFI.ECDH
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.SecureBytes

-- | Compute a shared secret using ECDH (FIPS-compliant variant).
-- The output is a hash of the shared point x-coordinate. The output
-- length determines which hash is used internally:
-- 32 -> SHA-256, 48 -> SHA-384, 64 -> SHA-512.
ecdhComputeSecret :: ECKeyPair -> ECPublicKey -> Int -> Either CryptoError SecureBytes
ecdhComputeSecret myKey peerPub outLen
  | outLen `notElem` [32, 48, 64] =
      Left (InvalidInput "ecdhComputeSecret: output length must be 32, 48, or 64")
  | otherwise = unsafePerformIO $ withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> runExceptT $ do
      peerPoint <- liftIO $ c_EC_KEY_get0_public_key peerKeyPtr
      liftIO clearBoringSSLError
      ssSB <- liftIO $ createSecureBytes outLen $ \_ -> return ()
      rc <- liftIO $ withSecureBytes ssSB $ \ptr _ ->
        c_ECDH_compute_key_fips (castPtr ptr) (fromIntegral outLen) peerPoint myKeyPtr
      checkRCError "ecdhComputeSecret: ECDH_compute_key_fips failed" rc
      return ssSB

-- | Compute a raw ECDH shared secret (x-coordinate of shared point).
-- Returns the x-coordinate of privKey * peerPubKey, zero-padded to the
-- field size: 32 bytes for P-256, 48 for P-384, 66 for P-521.
ecdhComputeRawSecret :: ECKeyPair -> ECPublicKey -> Either CryptoError SecureBytes
ecdhComputeRawSecret myKey peerPub = unsafePerformIO $ withBoundThread $
  withECKeyPair myKey $ \myKeyPtr ->
    withECPublicKey peerPub $ \peerKeyPtr -> runExceptT $ do
      groupPtr <- liftIO (c_EC_KEY_get0_group myKeyPtr)
        >>= nonNull (OperationFailed "ecdhComputeRawSecret: EC_KEY_get0_group returned NULL")
      degree <- liftIO $ c_EC_GROUP_get_degree groupPtr
      let fieldBytes = fromIntegral ((degree + 7) `div` 8) :: Int
      privBn <- liftIO (c_EC_KEY_get0_private_key myKeyPtr)
        >>= nonNull (OperationFailed "ecdhComputeRawSecret: no private key")
      peerPoint <- liftIO (c_EC_KEY_get0_public_key peerKeyPtr)
        >>= nonNull (OperationFailed "ecdhComputeRawSecret: no peer public key")
      sharedPt <- liftIO (c_EC_POINT_new groupPtr)
        >>= nonNull (AllocationFailure "ecdhComputeRawSecret: EC_POINT_new failed")
      flip finallyE (c_EC_POINT_free sharedPt) $ do
        liftIO clearBoringSSLError
        rc <- liftIO $ c_EC_POINT_mul groupPtr sharedPt nullPtr peerPoint privBn nullPtr
        checkRCError "ecdhComputeRawSecret: EC_POINT_mul failed" rc
        xBn <- liftIO c_BN_new
          >>= nonNull (AllocationFailure "ecdhComputeRawSecret: BN_new failed")
        flip finallyE (c_BN_clear_free xBn) $ do
          rc2 <- liftIO $ c_EC_POINT_get_affine_coordinates_GFp groupPtr sharedPt xBn nullPtr nullPtr
          checkRCError "ecdhComputeRawSecret: get_affine_coordinates failed" rc2
          ssSB <- liftIO $ createSecureBytes fieldBytes $ \_ -> return ()
          rc3 <- liftIO $ withSecureBytes ssSB $ \ptr _ ->
            c_BN_bn2bin_padded (castPtr ptr) (fromIntegral fieldBytes) xBn
          checkRC (OperationFailed "ecdhComputeRawSecret: BN_bn2bin_padded failed") rc3
          return ssSB

{-# NOINLINE ecdhComputeSecret #-}
{-# NOINLINE ecdhComputeRawSecret #-}
