-- | Ed25519 digital signatures (RFC 8032).
--
-- Provides key generation, deterministic signing, and signature verification.
-- Signing is pure and deterministic per RFC 8032.
module Crypto.BoringSSL.Ed25519
  ( -- * Key types
    PublicKey
  , PrivateKey
  , Signature
    -- * Key generation
  , generateKeyPair
  , keyPairFromSeed
    -- * Signing and verification
  , sign
  , verify
    -- * Serialization
  , publicKeyToBytes
  , privateKeyToBytes
  , signatureToBytes
  , publicKeyFromBytes
  , privateKeyFromBytes
  , signatureFromBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Ed25519
import Crypto.BoringSSL.Internal.SecureBytes

-- | An Ed25519 public key (32 bytes).
newtype PublicKey = PublicKey ByteString
  deriving (Eq, Show)

-- | An Ed25519 private key (64 bytes: seed + public key).
-- Backed by 'SecureBytes' so the key material is zeroized on finalization.
newtype PrivateKey = PrivateKey SecureBytes

instance Eq PrivateKey where
  PrivateKey a == PrivateKey b = secureBytesEq a b

instance Show PrivateKey where
  show _ = "PrivateKey <redacted>"

-- | An Ed25519 signature (64 bytes).
newtype Signature = Signature ByteString
  deriving (Eq, Show)

-- | Extract the raw bytes from a public key.
publicKeyToBytes :: PublicKey -> ByteString
publicKeyToBytes (PublicKey bs) = bs

-- | Extract the raw bytes from a private key.
-- Note: this creates a non-cleansed copy of the key material.
privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes (PrivateKey sb) = secureBytesToByteString sb

-- | Extract the raw bytes from a signature.
signatureToBytes :: Signature -> ByteString
signatureToBytes (Signature bs) = bs

-- | Construct a public key from exactly 32 bytes.
publicKeyFromBytes :: ByteString -> Either CryptoError PublicKey
publicKeyFromBytes bs
  | BS.length bs == 32 = Right (PublicKey bs)
  | otherwise = Left (InvalidInput ("publicKeyFromBytes: expected 32 bytes, got " ++ show (BS.length bs)))

-- | Construct a private key from exactly 64 bytes.
privateKeyFromBytes :: ByteString -> Either CryptoError PrivateKey
privateKeyFromBytes bs
  | BS.length bs == 64 = Right . PrivateKey $ unsafePerformIO $
      withByteString bs $ \srcPtr _ ->
        createSecureBytes 64 $ \dstPtr ->
          copyBytes (castPtr dstPtr) (castPtr srcPtr) 64
  | otherwise = Left (InvalidInput ("privateKeyFromBytes: expected 64 bytes, got " ++ show (BS.length bs)))
{-# NOINLINE privateKeyFromBytes #-}

-- | Construct a signature from exactly 64 bytes.
signatureFromBytes :: ByteString -> Either CryptoError Signature
signatureFromBytes bs
  | BS.length bs == 64 = Right (Signature bs)
  | otherwise = Left (InvalidInput ("signatureFromBytes: expected 64 bytes, got " ++ show (BS.length bs)))

-- | Generate a random Ed25519 key pair.
generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = do
  pubFPtr <- BSI.mallocByteString 32
  privSB <- createSecureBytes 64 $ \privPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      c_ED25519_keypair (castPtr pubPtr) privPtr
  return (PublicKey (BSI.BS pubFPtr 32), PrivateKey privSB)

-- | Deterministically derive a key pair from a 32-byte seed (pure, RFC 8032).
keyPairFromSeed :: ByteString -> Either CryptoError (PublicKey, PrivateKey)
keyPairFromSeed seed
  | BS.length seed /= 32 = Left (InvalidInput "keyPairFromSeed: seed must be 32 bytes")
  | otherwise = unsafePerformIO $ do
      pubFPtr <- BSI.mallocByteString 32
      privSB <- createSecureBytes 64 $ \privPtr ->
        withByteString seed $ \seedPtr _ ->
          withForeignPtr pubFPtr $ \pubPtr ->
            c_ED25519_keypair_from_seed (castPtr pubPtr) privPtr seedPtr
      return (Right (PublicKey (BSI.BS pubFPtr 32), PrivateKey privSB))
{-# NOINLINE keyPairFromSeed #-}

-- | Sign a message with an Ed25519 private key (pure, RFC 8032 deterministic).
sign :: PrivateKey -> ByteString -> Either CryptoError Signature
sign (PrivateKey privSB) msg = unsafePerformIO $
  withByteString msg $ \msgPtr msgLen ->
    withSecureBytes privSB $ \privPtr _ -> do
      sigFPtr <- BSI.mallocByteString 64
      rc <- withForeignPtr sigFPtr $ \sigPtr ->
        c_ED25519_sign (castPtr sigPtr) msgPtr msgLen privPtr
      if rc /= 1
        then return (Left (OperationFailed "Ed25519.sign: ED25519_sign failed"))
        else return (Right (Signature (BSI.BS sigFPtr 64)))
{-# NOINLINE sign #-}

-- | Verify an Ed25519 signature (pure).
verify :: PublicKey -> ByteString -> Signature -> Bool
verify (PublicKey pubKey) msg (Signature sig) = unsafePerformIO $
  withByteString msg $ \msgPtr msgLen ->
    withByteString sig $ \sigPtr _ ->
      withByteString pubKey $ \pubPtr _ -> do
        rc <- c_ED25519_verify msgPtr msgLen sigPtr pubPtr
        return (rc == 1)
{-# NOINLINE verify #-}
