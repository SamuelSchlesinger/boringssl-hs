-- | X25519 Diffie-Hellman key exchange (RFC 7748).
--
-- Provides key pair generation and shared secret computation using
-- Curve25519 scalar multiplication.
module Crypto.BoringSSL.X25519
  ( -- * Key types
    PublicKey
  , PrivateKey
    -- * Key generation
  , generateKeyPair
  , publicFromPrivate
    -- * Key exchange
  , computeSharedSecret
    -- * Serialization
  , publicKeyToBytes
  , privateKeyToBytes
  , publicKeyFromBytes
  , privateKeyFromBytes
    -- * Error type
  , BoringSSLError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString, createByteString, constTimeEq)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.X25519

-- | An X25519 public key (32 bytes).
newtype PublicKey = PublicKey ByteString
  deriving (Eq, Show)

-- | An X25519 private key (32 bytes).
newtype PrivateKey = PrivateKey ByteString

instance Eq PrivateKey where
  PrivateKey a == PrivateKey b = constTimeEq a b

instance Show PrivateKey where
  show _ = "PrivateKey <redacted>"

-- | Extract the raw bytes from a public key.
publicKeyToBytes :: PublicKey -> ByteString
publicKeyToBytes (PublicKey bs) = bs

-- | Extract the raw bytes from a private key.
privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes (PrivateKey bs) = bs

-- | Construct a public key from exactly 32 bytes.
publicKeyFromBytes :: ByteString -> Maybe PublicKey
publicKeyFromBytes bs
  | BS.length bs == 32 = Just (PublicKey bs)
  | otherwise = Nothing

-- | Construct a private key from exactly 32 bytes.
privateKeyFromBytes :: ByteString -> Maybe PrivateKey
privateKeyFromBytes bs
  | BS.length bs == 32 = Just (PrivateKey bs)
  | otherwise = Nothing

-- | Generate a random X25519 key pair.
generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = do
  pubFPtr <- BSI.mallocByteString 32
  privFPtr <- BSI.mallocByteString 32
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr privFPtr $ \privPtr ->
      c_X25519_keypair (castPtr pubPtr) (castPtr privPtr)
  return (PublicKey (BSI.BS pubFPtr 32), PrivateKey (BSI.BS privFPtr 32))

-- | Derive the public key from a private key (pure, deterministic).
publicFromPrivate :: PrivateKey -> PublicKey
publicFromPrivate (PrivateKey privKey) = unsafePerformIO $ do
  pub <- createByteString 32 $ \pubPtr ->
    withByteString privKey $ \privPtr _ ->
      c_X25519_public_from_private pubPtr privPtr
  return (PublicKey pub)
{-# NOINLINE publicFromPrivate #-}

-- | Compute a shared secret via X25519 Diffie-Hellman.
-- Returns 'Left' if the peer's public key is a low-order point.
-- Pure: X25519 scalar multiplication is deterministic.
computeSharedSecret :: PrivateKey -> PublicKey -> Either BoringSSLError ByteString
computeSharedSecret (PrivateKey privKey) (PublicKey pubKey) = unsafePerformIO $ do
  outFPtr <- BSI.mallocByteString 32
  rc <- withForeignPtr outFPtr $ \outPtr ->
    withByteString privKey $ \privPtr _ ->
      withByteString pubKey $ \pubPtr _ ->
        c_X25519 (castPtr outPtr) privPtr pubPtr
  if rc == 1
    then return (Right (BSI.BS outFPtr 32))
    else return (Left (BoringSSLError 0 "X25519.computeSharedSecret: low-order point"))
{-# NOINLINE computeSharedSecret #-}
