-- | Post-quantum ML-KEM (Kyber) key encapsulation mechanism.
--
-- Provides ML-KEM-768 and ML-KEM-1024 for post-quantum key exchange.
-- ML-KEM-768 is recommended for most uses. ML-KEM-1024 is available
-- for higher security margins.
module Crypto.BoringSSL.MLKEM
  ( MLKEMVariant(..)
  , MLKEMPrivateKey
  , generateKeyPair
  , encapsulate
  , encapsulatePublic
  , decapsulate
    -- * Constants
  , publicKeyBytes
  , ciphertextBytes
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Control.Exception (mask_)
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.CBS
import Crypto.BoringSSL.Internal.FFI.MLKEM
import Crypto.BoringSSL.Internal.SecureBytes

-- | ML-KEM variant selection.
data MLKEMVariant = MLKEM768 | MLKEM1024
  deriving (Eq, Show)

-- | An opaque ML-KEM private key. Contains variant information and
-- the private key struct data managed by a ForeignPtr.
data MLKEMPrivateKey = MLKEMPrivateKey !MLKEMVariant !(ForeignPtr ())

instance Show MLKEMPrivateKey where
  show (MLKEMPrivateKey v _) = "MLKEMPrivateKey " ++ show v ++ " <redacted>"

-- | Query the encoded public key size for a variant.
publicKeyBytes :: MLKEMVariant -> Int
publicKeyBytes MLKEM768  = mlkem768PublicKeyBytes
publicKeyBytes MLKEM1024 = mlkem1024PublicKeyBytes

-- | Query the ciphertext size for a variant.
ciphertextBytes :: MLKEMVariant -> Int
ciphertextBytes MLKEM768  = mlkem768CiphertextBytes
ciphertextBytes MLKEM1024 = mlkem1024CiphertextBytes

-- | Generate a random ML-KEM key pair.
-- Returns the encoded public key and an opaque private key.
generateKeyPair :: MLKEMVariant -> IO (ByteString, MLKEMPrivateKey)
generateKeyPair MLKEM768 = mask_ $ do
  let pkSize = mlkem768PublicKeyBytes
      skSize = mlkem768PrivateKeySize
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocForeignPtrBytes skSize
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_MLKEM768_generate_key (castPtr pubPtr) nullPtr (castPtr skPtr)
  return (BSI.BS pubFPtr pkSize, MLKEMPrivateKey MLKEM768 skFPtr)

generateKeyPair MLKEM1024 = mask_ $ do
  let pkSize = mlkem1024PublicKeyBytes
      skSize = mlkem1024PrivateKeySize
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocForeignPtrBytes skSize
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_MLKEM1024_generate_key (castPtr pubPtr) nullPtr (castPtr skPtr)
  return (BSI.BS pubFPtr pkSize, MLKEMPrivateKey MLKEM1024 skFPtr)

-- | Encapsulate a shared secret using a private key.
-- Derives the public key struct from the private key internally,
-- then performs encapsulation.
-- Returns @(ciphertext, sharedSecret)@. The shared secret is returned as
-- 'SecureBytes' and zeroized on finalization.
--
-- Note: For standard KEM usage where you only have the peer's public key,
-- use 'encapsulatePublic' instead.
encapsulate :: MLKEMPrivateKey -> IO (ByteString, SecureBytes)
encapsulate (MLKEMPrivateKey MLKEM768 skFPtr) = mask_ $ do
  let ctSize = mlkem768CiphertextBytes
      pkStructSize = mlkem768PublicKeySize
  ctFPtr <- BSI.mallocByteString ctSize
  ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      c_MLKEM768_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
      withForeignPtr ctFPtr $ \ctPtr ->
        withSecureBytes ssSB $ \ssPtr _ ->
          c_MLKEM768_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
  return (BSI.BS ctFPtr ctSize, ssSB)

encapsulate (MLKEMPrivateKey MLKEM1024 skFPtr) = mask_ $ do
  let ctSize = mlkem1024CiphertextBytes
      pkStructSize = mlkem1024PublicKeySize
  ctFPtr <- BSI.mallocByteString ctSize
  ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      c_MLKEM1024_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
      withForeignPtr ctFPtr $ \ctPtr ->
        withSecureBytes ssSB $ \ssPtr _ ->
          c_MLKEM1024_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
  return (BSI.BS ctFPtr ctSize, ssSB)

-- | Encapsulate a shared secret using an encoded public key (the standard KEM API).
-- Takes the encoded public key bytes (from 'generateKeyPair') rather than a
-- private key. Returns @(ciphertext, sharedSecret)@. The shared secret is
-- returned as 'SecureBytes' and zeroized on finalization.
encapsulatePublic :: MLKEMVariant -> ByteString -> IO (Either CryptoError (ByteString, SecureBytes))
encapsulatePublic MLKEM768 pubKeyBytes
  | BS.length pubKeyBytes /= mlkem768PublicKeyBytes =
      return (Left (InvalidInput "MLKEM.encapsulatePublic: incorrect public key length"))
  | otherwise = do
      let ctSize = mlkem768CiphertextBytes
          pkStructSize = mlkem768PublicKeySize
      ctFPtr <- BSI.mallocByteString ctSize
      ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
      allocaBytes pkStructSize $ \pkStructPtr ->
        withByteString pubKeyBytes $ \pkBytesPtr pkBytesLen ->
          allocaBytes c_bssl_CBS_size $ \cbsPtr -> do
            c_bssl_CBS_init cbsPtr (castPtr pkBytesPtr) pkBytesLen
            rc <- c_MLKEM768_parse_public_key (castPtr pkStructPtr) (castPtr cbsPtr)
            if rc /= 1
              then return (Left (DecodeError "MLKEM.encapsulatePublic: failed to parse public key"))
              else do
                withForeignPtr ctFPtr $ \ctPtr ->
                  withSecureBytes ssSB $ \ssPtr _ ->
                    c_MLKEM768_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
                return (Right (BSI.BS ctFPtr ctSize, ssSB))

encapsulatePublic MLKEM1024 pubKeyBytes
  | BS.length pubKeyBytes /= mlkem1024PublicKeyBytes =
      return (Left (InvalidInput "MLKEM.encapsulatePublic: incorrect public key length"))
  | otherwise = do
      let ctSize = mlkem1024CiphertextBytes
          pkStructSize = mlkem1024PublicKeySize
      ctFPtr <- BSI.mallocByteString ctSize
      ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
      allocaBytes pkStructSize $ \pkStructPtr ->
        withByteString pubKeyBytes $ \pkBytesPtr pkBytesLen ->
          allocaBytes c_bssl_CBS_size $ \cbsPtr -> do
            c_bssl_CBS_init cbsPtr (castPtr pkBytesPtr) pkBytesLen
            rc <- c_MLKEM1024_parse_public_key (castPtr pkStructPtr) (castPtr cbsPtr)
            if rc /= 1
              then return (Left (DecodeError "MLKEM.encapsulatePublic: failed to parse public key"))
              else do
                withForeignPtr ctFPtr $ \ctPtr ->
                  withSecureBytes ssSB $ \ssPtr _ ->
                    c_MLKEM1024_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
                return (Right (BSI.BS ctFPtr ctSize, ssSB))

-- | Decapsulate a shared secret from a ciphertext using a private key.
-- The shared secret is returned as 'SecureBytes' and zeroized on finalization.
decapsulate :: MLKEMPrivateKey -> ByteString -> IO (Either CryptoError SecureBytes)
decapsulate (MLKEMPrivateKey MLKEM768 skFPtr) ciphertext
  | BS.length ciphertext /= mlkem768CiphertextBytes =
      return (Left (InvalidInput "MLKEM.decapsulate: incorrect ciphertext length"))
  | otherwise = do
      ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString ciphertext $ \ctPtr ctLen ->
          withSecureBytes ssSB $ \ssPtr _ ->
            c_MLKEM768_decap ssPtr ctPtr ctLen (castPtr skPtr)
      if rc == 1
        then return (Right ssSB)
        else return (Left (OperationFailed "MLKEM.decapsulate: decapsulation failed"))

decapsulate (MLKEMPrivateKey MLKEM1024 skFPtr) ciphertext
  | BS.length ciphertext /= mlkem1024CiphertextBytes =
      return (Left (InvalidInput "MLKEM.decapsulate: incorrect ciphertext length"))
  | otherwise = do
      ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString ciphertext $ \ctPtr ctLen ->
          withSecureBytes ssSB $ \ssPtr _ ->
            c_MLKEM1024_decap ssPtr ctPtr ctLen (castPtr skPtr)
      if rc == 1
        then return (Right ssSB)
        else return (Left (OperationFailed "MLKEM.decapsulate: decapsulation failed"))
