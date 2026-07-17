-- | X-Wing hybrid post-quantum key encapsulation mechanism.
--
-- X-Wing combines ML-KEM-768 and X25519 into a single KEM, providing
-- post-quantum security from ML-KEM-768 and classical security from X25519.
-- See <https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06>.
--
-- __Implicit rejection__: like ML-KEM (FIPS 203), 'decapsulate' never
-- fails on a well-formed-length ciphertext — a tampered ciphertext
-- yields 'Right' with a pseudo-random secret that will not match the
-- encapsulator\'s. Do not test for tampering by expecting 'Left'.
module Crypto.BoringSSL.XWing
  ( XWingPublicKey
  , XWingPrivateKey
  , generateKeyPair
  , publicFromPrivate
  , encapsulate
  , decapsulate
    -- * Public key serialization
  , publicKeyFromBytes
  , publicKeyToBytes
    -- * Constants
  , publicKeyBytes
  , ciphertextBytes
  , sharedSecretBytes
  , privateKeyBytes
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
import Crypto.BoringSSL.Internal.SecureBytes
import System.IO.Unsafe (unsafePerformIO)

-- | An X-Wing public key: validated, encoded bytes ('publicKeyBytes'
-- long). Build one with 'publicKeyFromBytes' or 'generateKeyPair'.
newtype XWingPublicKey = XWingPublicKey ByteString
  deriving (Eq)

instance Show XWingPublicKey where
  show _ = "XWingPublicKey"

-- | Encoded public key size in bytes (1216).
publicKeyBytes :: Int
publicKeyBytes = xwingPublicKeyBytes

-- | Ciphertext size in bytes (1120).
ciphertextBytes :: Int
ciphertextBytes = xwingCiphertextBytes

-- | Shared secret size in bytes (32).
sharedSecretBytes :: Int
sharedSecretBytes = xwingSharedSecretBytes

-- | Encoded private key (seed) size in bytes.
privateKeyBytes :: Int
privateKeyBytes = xwingPrivateKeyBytes

-- | Validate (length) and wrap an encoded X-Wing public key.
publicKeyFromBytes :: ByteString -> Either CryptoError XWingPublicKey
publicKeyFromBytes bs
  | BS.length bs /= xwingPublicKeyBytes =
      Left (InvalidInput ("XWing.publicKeyFromBytes: expected "
        ++ show xwingPublicKeyBytes ++ " bytes, got " ++ show (BS.length bs)))
  | otherwise = Right (XWingPublicKey bs)

-- | The encoded bytes of a public key.
publicKeyToBytes :: XWingPublicKey -> ByteString
publicKeyToBytes (XWingPublicKey bs) = bs

-- | An opaque X-Wing private key. Wraps the large @XWING_private_key@ struct
-- via a 'ForeignPtr'. The struct contents must never leave the address space.
newtype XWingPrivateKey = XWingPrivateKey (ForeignPtr ())

instance Show XWingPrivateKey where
  show _ = "XWingPrivateKey <redacted>"

-- | Generate a random X-Wing key pair.
generateKeyPair :: IO (Either CryptoError (XWingPublicKey, XWingPrivateKey))
generateKeyPair = mask_ $ do
  pubFPtr <- BSI.mallocByteString xwingPublicKeyBytes
  skFPtr <- mallocSecureForeignPtr xwingPrivateKeyStructSize
  rc <- withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_XWING_generate_key (castPtr pubPtr) (castPtr skPtr)
  if rc == 1
    then return (Right ( XWingPublicKey (BSI.BS pubFPtr xwingPublicKeyBytes)
                       , XWingPrivateKey skFPtr ))
    else return (Left (OperationFailed "XWing.generateKeyPair: key generation failed"))

-- | Derive the public key from a private key. Pure: derivation is
-- deterministic.
publicFromPrivate :: XWingPrivateKey -> Either CryptoError XWingPublicKey
publicFromPrivate (XWingPrivateKey skFPtr) = unsafePerformIO $ do
  pubFPtr <- BSI.mallocByteString xwingPublicKeyBytes
  rc <- withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_XWING_public_from_private (castPtr pubPtr) (castPtr skPtr)
  if rc == 1
    then return (Right (XWingPublicKey (BSI.BS pubFPtr xwingPublicKeyBytes)))
    else return (Left (OperationFailed "XWing.publicFromPrivate: derivation failed"))
{-# NOINLINE publicFromPrivate #-}

-- | Encapsulate a shared secret to a peer\'s public key. In 'IO'
-- because encapsulation is randomized. Returns
-- @Right (ciphertext, sharedSecret)@; the shared secret lives in
-- 'SecureBytes'.
encapsulate :: XWingPublicKey -> IO (Either CryptoError (ByteString, SecureBytes))
encapsulate (XWingPublicKey encodedPublicKey) = do
      ctFPtr <- BSI.mallocByteString xwingCiphertextBytes
      ssSB <- createSecureBytes xwingSharedSecretBytes $ \_ -> return ()
      rc <- withForeignPtr ctFPtr $ \ctPtr ->
        withSecureBytes ssSB $ \ssPtr _ ->
          withByteString encodedPublicKey $ \pkPtr _pkLen ->
            c_XWING_encap (castPtr ctPtr) (castPtr ssPtr) pkPtr
      if rc == 1
        then return (Right ( BSI.BS ctFPtr xwingCiphertextBytes
                           , ssSB
                           ))
        else return (Left (OperationFailed "XWing.encapsulate: encapsulation failed"))

-- | Decapsulate a shared secret from a ciphertext using a private key.
-- Pure: decapsulation is deterministic. __Remember implicit rejection__
-- (module header): tampering yields 'Right' with a mismatching secret,
-- not 'Left'.
decapsulate :: XWingPrivateKey -> ByteString -> Either CryptoError SecureBytes
decapsulate (XWingPrivateKey skFPtr) ciphertext
  | BS.length ciphertext /= xwingCiphertextBytes =
      Left (InvalidInput ("XWing.decapsulate: expected "
        ++ show xwingCiphertextBytes ++ "-byte ciphertext, got "
        ++ show (BS.length ciphertext)))
  | otherwise = unsafePerformIO $ do
      ssSB <- createSecureBytes xwingSharedSecretBytes $ \_ -> return ()
      rc <- withSecureBytes ssSB $ \ssPtr _ ->
        withByteString ciphertext $ \ctPtr _ctLen ->
          withForeignPtr skFPtr $ \skPtr ->
            c_XWING_decap (castPtr ssPtr) ctPtr (castPtr skPtr)
      if rc == 1
        then return (Right ssSB)
        else return (Left (OperationFailed "XWing.decapsulate: decapsulation failed"))
{-# NOINLINE decapsulate #-}
