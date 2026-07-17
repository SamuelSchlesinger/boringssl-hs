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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString, createByteString)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.X25519
import Crypto.BoringSSL.Internal.SecureBytes

-- | An X25519 public key (32 bytes).
newtype PublicKey = PublicKey ByteString
  deriving (Eq, Show)

-- | An X25519 private key (32 bytes).
-- Backed by 'SecureBytes' so the key material is zeroized on finalization.
newtype PrivateKey = PrivateKey SecureBytes

instance Eq PrivateKey where
  PrivateKey a == PrivateKey b = secureBytesEq a b

instance Show PrivateKey where
  show _ = "PrivateKey <redacted>"

-- | Extract the raw bytes from a public key.
publicKeyToBytes :: PublicKey -> ByteString
publicKeyToBytes (PublicKey bs) = bs

-- | Extract the raw bytes from a private key.
-- Note: this creates a non-cleansed copy of the key material.
privateKeyToBytes :: PrivateKey -> ByteString
privateKeyToBytes (PrivateKey sb) = secureBytesToByteString sb

-- | Construct a public key from exactly 32 bytes.
publicKeyFromBytes :: ByteString -> Either CryptoError PublicKey
publicKeyFromBytes bs
  | BS.length bs == 32 = Right (PublicKey bs)
  | otherwise = Left (InvalidInput ("publicKeyFromBytes: expected 32 bytes, got " ++ show (BS.length bs)))

-- | Construct a private key from exactly 32 bytes.
privateKeyFromBytes :: ByteString -> Either CryptoError PrivateKey
privateKeyFromBytes bs
  | BS.length bs == 32 = Right . PrivateKey $ unsafePerformIO $
      withByteString bs $ \srcPtr _ ->
        createSecureBytes 32 $ \dstPtr ->
          copyBytes (castPtr dstPtr) (castPtr srcPtr) 32
  | otherwise = Left (InvalidInput ("privateKeyFromBytes: expected 32 bytes, got " ++ show (BS.length bs)))
{-# NOINLINE privateKeyFromBytes #-}

-- | Generate a random X25519 key pair.
generateKeyPair :: IO (PublicKey, PrivateKey)
generateKeyPair = do
  pubFPtr <- BSI.mallocByteString 32
  privSB <- createSecureBytes 32 $ \privPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      c_X25519_keypair (castPtr pubPtr) privPtr
  return (PublicKey (BSI.BS pubFPtr 32), PrivateKey privSB)

-- | Derive the public key from a private key (pure, deterministic).
publicFromPrivate :: PrivateKey -> PublicKey
publicFromPrivate (PrivateKey privSB) = unsafePerformIO $ do
  pub <- createByteString 32 $ \pubPtr ->
    withSecureBytes privSB $ \privPtr _ ->
      c_X25519_public_from_private pubPtr privPtr
  return (PublicKey pub)
{-# NOINLINE publicFromPrivate #-}

-- | Compute a shared secret via X25519 Diffie-Hellman.
-- Returns 'Left' if the peer's public key is a low-order point.
-- The shared secret is returned as 'SecureBytes' so it is zeroized on
-- finalization.
-- Pure: X25519 scalar multiplication is deterministic.
computeSharedSecret :: PrivateKey -> PublicKey -> Either CryptoError SecureBytes
computeSharedSecret (PrivateKey privSB) (PublicKey pubKey) = unsafePerformIO $ do
  ssSB <- createSecureBytes 32 $ \_ -> return ()  -- will be overwritten
  rc <- withSecureBytes ssSB $ \outPtr _ ->
    withSecureBytes privSB $ \privPtr _ ->
      withByteString pubKey $ \pubPtr _ ->
        c_X25519 outPtr privPtr pubPtr
  if rc == 1
    then return (Right ssSB)
    else return (Left (OperationFailed "X25519.computeSharedSecret: low-order point"))
{-# NOINLINE computeSharedSecret #-}
