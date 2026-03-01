-- | SLH-DSA stateless hash-based post-quantum signatures (FIPS 205).
--
-- Provides key generation, signing, and verification for SLH-DSA-SHA2-128s
-- and SLH-DSA-SHAKE-256f parameter sets. Keys and signatures are represented
-- as raw 'ByteString' values.
--
-- Note: SLH-DSA signing is very slow by design. The sign functions use safe
-- foreign calls to avoid blocking other Haskell threads.
module Crypto.BoringSSL.SLHDSA
  ( -- * Variant selection
    SLHDSAVariant(..)
    -- * Key generation
  , generateKeyPair
    -- * Signing and verification
  , sign
  , verify
    -- * Size queries
  , publicKeyBytes
  , privateKeyBytes
  , signatureBytes
    -- * Secure memory
  , SecureBytes
  , createSecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Control.Exception (mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.SLHDSA
import Crypto.BoringSSL.Internal.SecureBytes

-- | SLH-DSA parameter set variant.
data SLHDSAVariant
  = SHA2_128S   -- ^ SLH-DSA-SHA2-128s: 32-byte public key, 64-byte private key, 7856-byte signature
  | SHAKE_256F  -- ^ SLH-DSA-SHAKE-256f: 64-byte public key, 128-byte private key, 49856-byte signature
  deriving (Eq, Show)

-- | Return the public key size in bytes for the given variant.
publicKeyBytes :: SLHDSAVariant -> Int
publicKeyBytes SHA2_128S  = slhdsaSha2128sPublicKeyBytes
publicKeyBytes SHAKE_256F = slhdsaShake256fPublicKeyBytes

-- | Return the private key size in bytes for the given variant.
privateKeyBytes :: SLHDSAVariant -> Int
privateKeyBytes SHA2_128S  = slhdsaSha2128sPrivateKeyBytes
privateKeyBytes SHAKE_256F = slhdsaShake256fPrivateKeyBytes

-- | Return the signature size in bytes for the given variant.
signatureBytes :: SLHDSAVariant -> Int
signatureBytes SHA2_128S  = slhdsaSha2128sSignatureBytes
signatureBytes SHAKE_256F = slhdsaShake256fSignatureBytes

-- | Generate a random SLH-DSA key pair. Returns @(publicKey, privateKey)@.
-- The private key is backed by 'SecureBytes' and zeroized on finalization.
generateKeyPair :: SLHDSAVariant -> IO (ByteString, SecureBytes)
generateKeyPair variant = mask_ $ do
  let pubLen  = publicKeyBytes variant
      privLen = privateKeyBytes variant
  pubFPtr  <- BSI.mallocByteString pubLen
  privSB <- createSecureBytes privLen $ \privPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      case variant of
        SHA2_128S  -> c_SLHDSA_SHA2_128S_generate_key (castPtr pubPtr) privPtr
        SHAKE_256F -> c_SLHDSA_SHAKE_256F_generate_key (castPtr pubPtr) privPtr
  return (BSI.BS pubFPtr pubLen, privSB)

-- | Sign a message with an SLH-DSA private key.
--
-- Takes (privateKey, message, context) and returns the signature on
-- success, or an error if the context is longer than 255 bytes or the
-- private key has the wrong length.
--
-- This function is pure (uses 'unsafePerformIO'). Signing is deterministic
-- but very slow by design.
sign :: SLHDSAVariant -> SecureBytes -> ByteString -> ByteString -> Either CryptoError ByteString
sign variant privKey msg ctx
  | secureBytesLength privKey /= privateKeyBytes variant =
      Left (InvalidInput "SLHDSA.sign: incorrect private key length")
  | otherwise = unsafePerformIO $ do
      let sigLen = signatureBytes variant
      sigFPtr <- BSI.mallocByteString sigLen
      rc <- withForeignPtr sigFPtr $ \sigPtr ->
        withSecureBytes privKey $ \privPtr _ ->
          withByteString msg $ \msgPtr msgLen ->
            withByteString ctx $ \ctxPtr ctxLen ->
              case variant of
                SHA2_128S  -> c_SLHDSA_SHA2_128S_sign
                                (castPtr sigPtr) privPtr msgPtr msgLen ctxPtr ctxLen
                SHAKE_256F -> c_SLHDSA_SHAKE_256F_sign
                                (castPtr sigPtr) privPtr msgPtr msgLen ctxPtr ctxLen
      if rc == 1
        then return (Right (BSI.BS sigFPtr sigLen))
        else return (Left (OperationFailed "SLHDSA.sign: signing failed"))
{-# NOINLINE sign #-}

-- | Verify an SLH-DSA signature.
--
-- Takes (publicKey, signature, message, context) and returns @Right True@ if
-- the signature is valid, @Right False@ if invalid, or @Left@ for input
-- validation errors (e.g. wrong-length public key).
--
-- This function is pure (uses 'unsafePerformIO').
verify :: SLHDSAVariant -> ByteString -> ByteString -> ByteString -> ByteString -> Either CryptoError Bool
verify variant pubKey sig msg ctx
  | BS.length pubKey /= publicKeyBytes variant =
      Left (InvalidInput "verify: incorrect public key length")
  | otherwise = unsafePerformIO $
      withByteString sig $ \sigPtr sigLen ->
        withByteString pubKey $ \pubPtr _ ->
          withByteString msg $ \msgPtr msgLen ->
            withByteString ctx $ \ctxPtr ctxLen -> do
              rc <- case variant of
                SHA2_128S  -> c_SLHDSA_SHA2_128S_verify
                                sigPtr sigLen pubPtr msgPtr msgLen ctxPtr ctxLen
                SHAKE_256F -> c_SLHDSA_SHAKE_256F_verify
                                sigPtr sigLen pubPtr msgPtr msgLen ctxPtr ctxLen
              return (Right (rc == 1))
{-# NOINLINE verify #-}
