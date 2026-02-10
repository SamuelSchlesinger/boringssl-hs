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
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ECKey
import Crypto.BoringSSL.Internal.FFI.ECDSA

-- | Generate a new EC key pair for ECDSA.
generateKeyPair :: ECCurve -> IO (Either CryptoError ECKeyPair)
generateKeyPair = generateECKeyPair

-- | Sign a pre-hashed digest with ECDSA.
-- Returns a DER-encoded ASN.1 signature.
ecdsaSign :: ECKeyPair -> ByteString -> IO (Either CryptoError ByteString)
ecdsaSign kp digest = withBoundThread $
  withECKeyPair kp $ \keyPtr -> do
    maxSigLen <- c_ECDSA_size keyPtr
    fptr <- BSI.mallocByteString (fromIntegral maxSigLen)
    result <- withForeignPtr fptr $ \sigPtr ->
      withByteString digest $ \digestPtr digestLen ->
        alloca $ \sigLenPtr -> do
          clearBoringSSLError
          rc <- c_ECDSA_sign 0 digestPtr digestLen (castPtr sigPtr) sigLenPtr keyPtr
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (OperationFailed "ecdsaSign: ECDSA_sign failed") id merr))
            else do
              sigLen <- peek sigLenPtr
              return (Right (fromIntegral sigLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS fptr len))

-- | Verify an ECDSA signature on a pre-hashed digest.
-- Returns @Right True@ for valid, @Right False@ for invalid, or
-- @Left@ for internal errors (e.g. memory allocation failure).
ecdsaVerify :: ECPublicKey -> ByteString -> ByteString -> IO (Either CryptoError Bool)
ecdsaVerify pubKey digest sig = withBoundThread $
  withECPublicKey pubKey $ \keyPtr ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        clearBoringSSLError
        rc <- c_ECDSA_verify 0 digestPtr digestLen sigPtr sigLen keyPtr
        if rc == 1
          then return (Right True)
          else if rc == 0
            then return (Right False)
            else do
              merr <- getBoringSSLError
              return (Left (maybe (OperationFailed "ecdsaVerify: internal error") id merr))

-- | Sign a pre-hashed digest with ECDSA, producing a fixed-size P1363
-- signature (r || s, each zero-padded to the group order size).
-- The signature length is always @2 * group_order_bytes@
-- (64 for P-256, 96 for P-384, 132 for P-521).
ecdsaSignP1363 :: ECKeyPair -> ByteString -> IO (Either CryptoError ByteString)
ecdsaSignP1363 kp digest = withBoundThread $
  withECKeyPair kp $ \keyPtr -> do
    maxSigLen <- c_ECDSA_size_p1363 keyPtr
    fptr <- BSI.mallocByteString (fromIntegral maxSigLen)
    result <- withForeignPtr fptr $ \sigPtr ->
      withByteString digest $ \digestPtr digestLen ->
        alloca $ \sigLenPtr -> do
          clearBoringSSLError
          rc <- c_ECDSA_sign_p1363 digestPtr digestLen (castPtr sigPtr) sigLenPtr maxSigLen keyPtr
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (OperationFailed "ecdsaSignP1363: ECDSA_sign_p1363 failed") id merr))
            else do
              sigLen <- peek sigLenPtr
              return (Right (fromIntegral sigLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS fptr len))

-- | Verify a P1363 fixed-size ECDSA signature on a pre-hashed digest.
-- Returns @Right True@ for valid, @Right False@ for invalid, or
-- @Left@ for internal errors.
ecdsaVerifyP1363 :: ECPublicKey -> ByteString -> ByteString -> IO (Either CryptoError Bool)
ecdsaVerifyP1363 pubKey digest sig = withBoundThread $
  withECPublicKey pubKey $ \keyPtr ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        clearBoringSSLError
        rc <- c_ECDSA_verify_p1363 digestPtr digestLen sigPtr sigLen keyPtr
        if rc == 1
          then return (Right True)
          else if rc == 0
            then return (Right False)
            else do
              merr <- getBoringSSLError
              return (Left (maybe (OperationFailed "ecdsaVerifyP1363: internal error") id merr))
