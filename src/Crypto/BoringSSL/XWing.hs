-- | X-Wing hybrid post-quantum key encapsulation mechanism.
--
-- X-Wing combines ML-KEM-768 and X25519 into a single KEM, providing
-- post-quantum security from ML-KEM-768 and classical security from X25519.
-- See <https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06>.
module Crypto.BoringSSL.XWing
  ( XWingPrivateKey
  , generateKeyPair
  , publicFromPrivate
  , encapsulate
  , decapsulate
  , CryptoError(..)
  ) where

import Control.Exception (mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.XWing

-- | An opaque X-Wing private key. Wraps the large @XWING_private_key@ struct
-- via a 'ForeignPtr'. The struct contents must never leave the address space.
newtype XWingPrivateKey = XWingPrivateKey (ForeignPtr ())

instance Show XWingPrivateKey where
  show _ = "XWingPrivateKey <redacted>"

-- | Generate a random X-Wing key pair.
-- Returns the encoded public key (1216 bytes) and an opaque private key.
generateKeyPair :: IO (Either CryptoError (ByteString, XWingPrivateKey))
generateKeyPair = mask_ $ do
  pubFPtr <- BSI.mallocByteString xwingPublicKeyBytes
  skFPtr <- mallocForeignPtrBytes xwingPrivateKeyStructSize
  rc <- withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_XWING_generate_key (castPtr pubPtr) (castPtr skPtr)
  if rc == 1
    then return (Right (BSI.BS pubFPtr xwingPublicKeyBytes, XWingPrivateKey skFPtr))
    else return (Left (OperationFailed "XWing.generateKeyPair: key generation failed"))

-- | Derive the encoded public key (1216 bytes) from a private key.
publicFromPrivate :: XWingPrivateKey -> IO (Either CryptoError ByteString)
publicFromPrivate (XWingPrivateKey skFPtr) = do
  pubFPtr <- BSI.mallocByteString xwingPublicKeyBytes
  rc <- withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_XWING_public_from_private (castPtr pubPtr) (castPtr skPtr)
  if rc == 1
    then return (Right (BSI.BS pubFPtr xwingPublicKeyBytes))
    else return (Left (OperationFailed "XWing.publicFromPrivate: derivation failed"))

-- | Encapsulate a shared secret using an encoded public key.
-- Takes a 1216-byte encoded public key and returns
-- @Right (ciphertext, sharedSecret)@ on success.
encapsulate :: ByteString -> IO (Either CryptoError (ByteString, ByteString))
encapsulate encodedPublicKey
  | BS.length encodedPublicKey /= xwingPublicKeyBytes =
      return (Left (InvalidInput "XWing.encapsulate: public key must be 1216 bytes"))
  | otherwise = do
      ctFPtr <- BSI.mallocByteString xwingCiphertextBytes
      ssFPtr <- BSI.mallocByteString xwingSharedSecretBytes
      rc <- withForeignPtr ctFPtr $ \ctPtr ->
        withForeignPtr ssFPtr $ \ssPtr ->
          withByteString encodedPublicKey $ \pkPtr _pkLen ->
            c_XWING_encap (castPtr ctPtr) (castPtr ssPtr) pkPtr
      if rc == 1
        then return (Right ( BSI.BS ctFPtr xwingCiphertextBytes
                           , BSI.BS ssFPtr xwingSharedSecretBytes
                           ))
        else return (Left (OperationFailed "XWing.encapsulate: encapsulation failed"))

-- | Decapsulate a shared secret from a ciphertext using a private key.
decapsulate :: XWingPrivateKey -> ByteString -> IO (Either CryptoError ByteString)
decapsulate (XWingPrivateKey skFPtr) ciphertext
  | BS.length ciphertext /= xwingCiphertextBytes =
      return (Left (InvalidInput "XWing.decapsulate: ciphertext must be 1120 bytes"))
  | otherwise = do
      ssFPtr <- BSI.mallocByteString xwingSharedSecretBytes
      rc <- withForeignPtr ssFPtr $ \ssPtr ->
        withByteString ciphertext $ \ctPtr _ctLen ->
          withForeignPtr skFPtr $ \skPtr ->
            c_XWING_decap (castPtr ssPtr) ctPtr (castPtr skPtr)
      if rc == 1
        then return (Right (BSI.BS ssFPtr xwingSharedSecretBytes))
        else return (Left (OperationFailed "XWing.decapsulate: decapsulation failed"))
