module Crypto.BoringSSL.Ed25519
  ( PublicKey
  , PrivateKey
  , Signature
  , generateKeyPair
  , keyPairFromSeed
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
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.Ed25519

-- | An Ed25519 public key (32 bytes).
newtype PublicKey = PublicKey ByteString
  deriving (Eq, Show)

-- | An Ed25519 private key (64 bytes: seed + public key).
newtype PrivateKey = PrivateKey ByteString
  deriving (Eq)

instance Show PrivateKey where
  show _ = "PrivateKey <redacted>"

-- | An Ed25519 signature (64 bytes).
newtype Signature = Signature ByteString
  deriving (Eq, Show)

-- | Extract the raw bytes from a public key.
publicKeyToBytes :: PublicKey -> ByteString
publicKeyToBytes (PublicKey bs) = bs

-- | Extract the raw bytes from a private key.
privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes (PrivateKey bs) = bs

-- | Extract the raw bytes from a signature.
signatureToBytes :: Signature -> ByteString
signatureToBytes (Signature bs) = bs

-- | Construct a public key from exactly 32 bytes.
publicKeyFromBytes :: ByteString -> Maybe PublicKey
publicKeyFromBytes bs
  | BS.length bs == 32 = Just (PublicKey bs)
  | otherwise = Nothing

-- | Construct a private key from exactly 64 bytes.
privateKeyFromBytes :: ByteString -> Maybe PrivateKey
privateKeyFromBytes bs
  | BS.length bs == 64 = Just (PrivateKey bs)
  | otherwise = Nothing

-- | Construct a signature from exactly 64 bytes.
signatureFromBytes :: ByteString -> Maybe Signature
signatureFromBytes bs
  | BS.length bs == 64 = Just (Signature bs)
  | otherwise = Nothing

-- | Generate a random Ed25519 key pair.
generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = do
  pubFPtr <- BSI.mallocByteString 32
  privFPtr <- BSI.mallocByteString 64
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr privFPtr $ \privPtr ->
      c_ED25519_keypair (castPtr pubPtr) (castPtr privPtr)
  return (PublicKey (BSI.BS pubFPtr 32), PrivateKey (BSI.BS privFPtr 64))

-- | Deterministically derive a key pair from a 32-byte seed (pure, RFC 8032).
keyPairFromSeed :: ByteString -> (PublicKey, PrivateKey)
keyPairFromSeed seed
  | BS.length seed /= 32 = error "keyPairFromSeed: seed must be 32 bytes"
  | otherwise = unsafePerformIO $ do
      pubFPtr <- BSI.mallocByteString 32
      privFPtr <- BSI.mallocByteString 64
      withByteString seed $ \seedPtr _ ->
        withForeignPtr pubFPtr $ \pubPtr ->
          withForeignPtr privFPtr $ \privPtr ->
            c_ED25519_keypair_from_seed (castPtr pubPtr) (castPtr privPtr) seedPtr
      return (PublicKey (BSI.BS pubFPtr 32), PrivateKey (BSI.BS privFPtr 64))
{-# NOINLINE keyPairFromSeed #-}

-- | Sign a message with an Ed25519 private key (pure, RFC 8032 deterministic).
sign :: PrivateKey -> ByteString -> Signature
sign (PrivateKey privKey) msg = unsafePerformIO $ do
  sig <- createByteString 64 $ \sigPtr ->
    withByteString msg $ \msgPtr msgLen ->
      withByteString privKey $ \privPtr _ -> do
        rc <- c_ED25519_sign sigPtr msgPtr msgLen privPtr
        if rc /= 1
          then fail "Ed25519.sign: ED25519_sign failed"
          else return ()
  return (Signature sig)
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
