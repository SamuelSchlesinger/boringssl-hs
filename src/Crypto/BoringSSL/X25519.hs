module Crypto.BoringSSL.X25519
  ( PublicKey(..)
  , PrivateKey(..)
  , generateKeyPair
  , publicFromPrivate
  , computeSharedSecret
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.X25519

-- | An X25519 public key (32 bytes).
newtype PublicKey = PublicKey ByteString
  deriving (Eq, Show)

-- | An X25519 private key (32 bytes).
newtype PrivateKey = PrivateKey ByteString
  deriving (Eq)

instance Show PrivateKey where
  show _ = "PrivateKey <redacted>"

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
-- Returns Nothing if the peer's public key is a low-order point.
-- Pure: X25519 scalar multiplication is deterministic.
computeSharedSecret :: PrivateKey -> PublicKey -> Maybe ByteString
computeSharedSecret (PrivateKey privKey) (PublicKey pubKey) = unsafePerformIO $ do
  outFPtr <- BSI.mallocByteString 32
  rc <- withForeignPtr outFPtr $ \outPtr ->
    withByteString privKey $ \privPtr _ ->
      withByteString pubKey $ \pubPtr _ ->
        c_X25519 (castPtr outPtr) privPtr pubPtr
  if rc == 1
    then return (Just (BSI.BS outFPtr 32))
    else return Nothing
{-# NOINLINE computeSharedSecret #-}
