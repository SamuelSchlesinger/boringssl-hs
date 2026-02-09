-- | Post-quantum ML-DSA-65 (Dilithium) digital signature scheme.
--
-- Provides ML-DSA-65 for post-quantum digital signatures.
module Crypto.BoringSSL.MLDSA
  ( MLDSA65PrivateKey
  , generateKeyPair
  , sign
  , verify
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.MLDSA

-- | An opaque ML-DSA-65 private key managed by a ForeignPtr.
newtype MLDSA65PrivateKey = MLDSA65PrivateKey (ForeignPtr ())

instance Show MLDSA65PrivateKey where
  show _ = "MLDSA65PrivateKey <redacted>"

-- | Generate a random ML-DSA-65 key pair.
-- Returns @(encodedPublicKey, privateKey)@.
generateKeyPair :: IO (ByteString, MLDSA65PrivateKey)
generateKeyPair = do
  let pkSize = mldsa65PublicKeyBytes
      skSize = mldsa65PrivateKeySize
      seedSize = mldsaSeedBytes
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocForeignPtrBytes skSize
  allocaBytes seedSize $ \seedPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      withForeignPtr skFPtr $ \skPtr -> do
        rc <- c_MLDSA65_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
        if rc /= 1
          then fail "MLDSA65_generate_key failed"
          else return ()
  return (BSI.BS pubFPtr pkSize, MLDSA65PrivateKey skFPtr)

-- | Sign a message with an ML-DSA-65 private key.
-- Takes a private key, message, and context string.
-- Returns @Just signature@ on success, or @Nothing@ on failure.
sign :: MLDSA65PrivateKey -> ByteString -> ByteString -> IO (Maybe ByteString)
sign (MLDSA65PrivateKey skFPtr) msg context = do
  let sigSize = mldsa65SignatureBytes
  sigFPtr <- BSI.mallocByteString sigSize
  rc <- withForeignPtr skFPtr $ \skPtr ->
    withByteString msg $ \msgPtr msgLen ->
      withByteString context $ \ctxPtr ctxLen ->
        withForeignPtr sigFPtr $ \sigPtr ->
          c_MLDSA65_sign (castPtr sigPtr) (castPtr skPtr)
            msgPtr msgLen ctxPtr ctxLen
  if rc == 1
    then return (Just (BSI.BS sigFPtr sigSize))
    else return Nothing

-- | Verify an ML-DSA-65 signature (pure).
-- Takes the private key (to derive the public key struct), signature,
-- message, and context. Returns True if the signature is valid.
--
-- Note: This function derives the public key struct from the private key
-- internally since the C API requires a parsed public key struct for
-- verification.
verify :: MLDSA65PrivateKey -> ByteString -> ByteString -> ByteString -> Bool
verify (MLDSA65PrivateKey skFPtr) sig msg context = unsafePerformIO $ do
  let pkStructSize = mldsa65PublicKeySize
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      rc1 <- c_MLDSA65_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
      if rc1 /= 1
        then return False
        else withByteString sig $ \sigPtr sigLen ->
          withByteString msg $ \msgPtr msgLen ->
            withByteString context $ \ctxPtr ctxLen -> do
              rc2 <- c_MLDSA65_verify (castPtr pkStructPtr)
                sigPtr sigLen msgPtr msgLen ctxPtr ctxLen
              return (rc2 == 1)
{-# NOINLINE verify #-}
