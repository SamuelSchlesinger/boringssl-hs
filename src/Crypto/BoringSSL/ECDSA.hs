module Crypto.BoringSSL.ECDSA
  ( ECCurve(..)
  , ECKeyPair
  , ECPublicKey
  , generateKeyPair
  , ecPublicKeyOfPair
  , ecdsaSign
  , ecdsaVerify
    -- * Key serialization
  , ecPublicKeyBytes
  , ecPrivateKeyBytes
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
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
generateKeyPair :: ECCurve -> IO ECKeyPair
generateKeyPair = generateECKeyPair

-- | Sign a pre-hashed digest with ECDSA.
-- Returns a DER-encoded ASN.1 signature.
ecdsaSign :: ECKeyPair -> ByteString -> IO (Either BoringSSLError ByteString)
ecdsaSign kp digest =
  withECKeyPair kp $ \keyPtr -> do
    maxSigLen <- c_ECDSA_size keyPtr
    fptr <- BSI.mallocByteString (fromIntegral maxSigLen)
    result <- withForeignPtr fptr $ \sigPtr ->
      withByteString digest $ \digestPtr digestLen ->
        alloca $ \sigLenPtr -> do
          rc <- c_ECDSA_sign 0 digestPtr digestLen (castPtr sigPtr) sigLenPtr keyPtr
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "ecdsaSign: ECDSA_sign failed") id merr))
            else do
              sigLen <- peek sigLenPtr
              return (Right (fromIntegral sigLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS fptr len))

-- | Verify an ECDSA signature on a pre-hashed digest.
ecdsaVerify :: ECPublicKey -> ByteString -> ByteString -> IO Bool
ecdsaVerify pubKey digest sig =
  withECPublicKey pubKey $ \keyPtr ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        rc <- c_ECDSA_verify 0 digestPtr digestLen sigPtr sigLen keyPtr
        return (rc == 1)
