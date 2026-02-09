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
  , decapsulate
    -- * Constants
  , publicKeyBytes
  , ciphertextBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.MLKEM

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
generateKeyPair MLKEM768 = do
  let pkSize = mlkem768PublicKeyBytes
      skSize = mlkem768PrivateKeySize
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocForeignPtrBytes skSize
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      c_MLKEM768_generate_key (castPtr pubPtr) nullPtr (castPtr skPtr)
  return (BSI.BS pubFPtr pkSize, MLKEMPrivateKey MLKEM768 skFPtr)

generateKeyPair MLKEM1024 = do
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
-- Returns @(ciphertext, sharedSecret)@.
encapsulate :: MLKEMPrivateKey -> IO (ByteString, ByteString)
encapsulate (MLKEMPrivateKey MLKEM768 skFPtr) = do
  let ctSize = mlkem768CiphertextBytes
      pkStructSize = mlkem768PublicKeySize
  ctFPtr <- BSI.mallocByteString ctSize
  ssFPtr <- BSI.mallocByteString mlkemSharedSecretBytes
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      c_MLKEM768_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
      withForeignPtr ctFPtr $ \ctPtr ->
        withForeignPtr ssFPtr $ \ssPtr ->
          c_MLKEM768_encap (castPtr ctPtr) (castPtr ssPtr) (castPtr pkStructPtr)
  return (BSI.BS ctFPtr ctSize, BSI.BS ssFPtr mlkemSharedSecretBytes)

encapsulate (MLKEMPrivateKey MLKEM1024 skFPtr) = do
  let ctSize = mlkem1024CiphertextBytes
      pkStructSize = mlkem1024PublicKeySize
  ctFPtr <- BSI.mallocByteString ctSize
  ssFPtr <- BSI.mallocByteString mlkemSharedSecretBytes
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      c_MLKEM1024_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
      withForeignPtr ctFPtr $ \ctPtr ->
        withForeignPtr ssFPtr $ \ssPtr ->
          c_MLKEM1024_encap (castPtr ctPtr) (castPtr ssPtr) (castPtr pkStructPtr)
  return (BSI.BS ctFPtr ctSize, BSI.BS ssFPtr mlkemSharedSecretBytes)

-- | Decapsulate a shared secret from a ciphertext using a private key.
-- Returns @Just sharedSecret@ on success, or @Nothing@ if the ciphertext
-- length is incorrect.
decapsulate :: MLKEMPrivateKey -> ByteString -> IO (Maybe ByteString)
decapsulate (MLKEMPrivateKey MLKEM768 skFPtr) ciphertext
  | BS.length ciphertext /= mlkem768CiphertextBytes = return Nothing
  | otherwise = do
      ssFPtr <- BSI.mallocByteString mlkemSharedSecretBytes
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString ciphertext $ \ctPtr ctLen ->
          withForeignPtr ssFPtr $ \ssPtr ->
            c_MLKEM768_decap (castPtr ssPtr) ctPtr ctLen (castPtr skPtr)
      if rc == 1
        then return (Just (BSI.BS ssFPtr mlkemSharedSecretBytes))
        else return Nothing

decapsulate (MLKEMPrivateKey MLKEM1024 skFPtr) ciphertext
  | BS.length ciphertext /= mlkem1024CiphertextBytes = return Nothing
  | otherwise = do
      ssFPtr <- BSI.mallocByteString mlkemSharedSecretBytes
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString ciphertext $ \ctPtr ctLen ->
          withForeignPtr ssFPtr $ \ssPtr ->
            c_MLKEM1024_decap (castPtr ssPtr) ctPtr ctLen (castPtr skPtr)
      if rc == 1
        then return (Just (BSI.BS ssFPtr mlkemSharedSecretBytes))
        else return Nothing
