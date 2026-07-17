-- | ECDSA digital signatures.
--
-- Supports P-256, P-384, and P-521 curves. Signatures are produced in
-- DER-encoded ASN.1 format or IEEE P1363 fixed-size format.
module Crypto.BoringSSL.ECDSA
  ( -- * Key types
    ECCurve(..)
  , ECKeyPair
  , ECPublicKey
    -- * Key generation
  , generateKeyPair
  , ecPublicKeyOfPair
    -- * Signing and verification (DER format)
  , ecdsaSign
  , ecdsaVerify
    -- * Signing and verification (P1363 fixed-size format)
  , ecdsaSignP1363
  , ecdsaVerifyP1363
    -- * Key serialization
  , ecPublicKeyBytes
  , ecPrivateKeyBytes
  , ecPrivateKeySecureBytes
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import System.IO.Unsafe (unsafePerformIO)
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.FFI.ECDSA

-- | Generate a fresh random ECDSA key pair for the given curve.
-- Uses BoringSSL's CSPRNG internally.
generateKeyPair :: ECCurve -> IO (Either CryptoError ECKeyPair)
generateKeyPair = generateECKeyPair

-- | Sign a pre-hashed digest with ECDSA.
-- Returns a DER-encoded ASN.1 signature.
--
-- The @digest@ parameter must be the output of a hash function (e.g.
-- 'Crypto.BoringSSL.Digest.hashSHA256'), /not/ the raw message.
-- Passing an unhashed message will produce a valid-looking but
-- semantically incorrect signature that no standard verifier will accept.
ecdsaSign :: ECKeyPair -> ByteString -> IO (Either CryptoError ByteString)
ecdsaSign kp digest = withBoundThread $
  withECKeyPair kp $ \keyPtr -> do
    maxSigLen <- c_ECDSA_size keyPtr
    withByteString digest $ \digestPtr digestLen -> runExceptT $ do
      fptr <- liftIO $ BSI.mallocByteString (fromIntegral maxSigLen)
      allocaE $ \sigLenPtr -> do
        liftIO clearBoringSSLError
        rc <- liftIO $ withForeignPtr fptr $ \sigPtr ->
          c_ECDSA_sign 0 digestPtr digestLen (castPtr sigPtr) sigLenPtr keyPtr
        checkRCError "ecdsaSign: ECDSA_sign failed" rc
        sigLen <- liftIO $ peek sigLenPtr
        return (BSI.BS fptr (fromIntegral sigLen))

-- | Verify an ECDSA signature on a pre-hashed digest.
-- The @digest@ must be the hash of the original message, matching
-- the hash used during signing.
--
-- Pure and fail-closed: 'False' covers invalid signatures, malformed
-- DER, and any internal failure.
ecdsaVerify :: ECPublicKey -> ByteString -> ByteString -> Bool
ecdsaVerify pubKey digest sig = unsafePerformIO $ withBoundThread $
  withECPublicKey pubKey $ \keyPtr ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        clearBoringSSLError
        rc <- c_ECDSA_verify 0 digestPtr digestLen sigPtr sigLen keyPtr
        clearBoringSSLError
        return (rc == 1)
{-# NOINLINE ecdsaVerify #-}

-- | Sign a pre-hashed digest with ECDSA, producing a fixed-size P1363
-- signature (r || s, each zero-padded to the group order size).
-- The signature length is always @2 * group_order_bytes@
-- (64 for P-256, 96 for P-384, 132 for P-521).
--
-- The @digest@ parameter must be the output of a hash function (e.g.
-- 'Crypto.BoringSSL.Digest.hashSHA256'), /not/ the raw message.
ecdsaSignP1363 :: ECKeyPair -> ByteString -> IO (Either CryptoError ByteString)
ecdsaSignP1363 kp digest = withBoundThread $
  withECKeyPair kp $ \keyPtr -> do
    maxSigLen <- c_ECDSA_size_p1363 keyPtr
    withByteString digest $ \digestPtr digestLen -> runExceptT $
      withOutputBuffer (fromIntegral maxSigLen)
        (\outPtr outLenPtr ->
          c_ECDSA_sign_p1363 digestPtr digestLen (castPtr outPtr) outLenPtr maxSigLen keyPtr)
        "ecdsaSignP1363: ECDSA_sign_p1363 failed"

-- | Verify a P1363 fixed-size ECDSA signature on a pre-hashed digest.
-- The @digest@ must be the hash of the original message, matching
-- the hash used during signing.
--
-- Pure and fail-closed: 'False' covers invalid signatures, wrong-length
-- input, and any internal failure.
ecdsaVerifyP1363 :: ECPublicKey -> ByteString -> ByteString -> Bool
ecdsaVerifyP1363 pubKey digest sig = unsafePerformIO $ withBoundThread $
  withECPublicKey pubKey $ \keyPtr ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        clearBoringSSLError
        rc <- c_ECDSA_verify_p1363 digestPtr digestLen sigPtr sigLen keyPtr
        clearBoringSSLError
        return (rc == 1)
{-# NOINLINE ecdsaVerifyP1363 #-}
