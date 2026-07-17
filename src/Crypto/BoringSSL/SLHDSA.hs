-- | SLH-DSA stateless hash-based post-quantum signatures (FIPS 205).
--
-- Provides key generation, signing, and verification for SLH-DSA-SHA2-128s
-- and SLH-DSA-SHAKE-256f parameter sets.
--
-- SLH-DSA signing is /very slow by design/ (especially SHAKE-256f) and,
-- per FIPS 205, BoringSSL implements the __randomized__ signing variant:
-- signing the same message twice yields different signatures, which is
-- why 'sign' lives in 'IO'.
module Crypto.BoringSSL.SLHDSA
  ( -- * Variant selection
    SLHDSAVariant(..)
    -- * Key types
  , SLHDSAPublicKey
    -- * Key generation
  , generateKeyPair
    -- * Signing and verification
  , sign
  , verify
    -- * Public key serialization
  , publicKeyFromBytes
  , publicKeyToBytes
    -- * Size queries
  , publicKeyBytes
  , privateKeyBytes
  , signatureBytes
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

-- | An SLH-DSA public key: variant-tagged, length-validated bytes.
data SLHDSAPublicKey = SLHDSAPublicKey !SLHDSAVariant !ByteString
  deriving (Eq)

instance Show SLHDSAPublicKey where
  show (SLHDSAPublicKey v _) = "SLHDSAPublicKey " ++ show v

-- | Validate (length) and wrap an encoded SLH-DSA public key.
publicKeyFromBytes :: SLHDSAVariant -> ByteString -> Either CryptoError SLHDSAPublicKey
publicKeyFromBytes variant bs
  | BS.length bs /= publicKeyBytes variant =
      Left (InvalidInput ("SLHDSA.publicKeyFromBytes: expected "
        ++ show (publicKeyBytes variant) ++ " bytes, got " ++ show (BS.length bs)))
  | otherwise = Right (SLHDSAPublicKey variant bs)

-- | The encoded bytes of a public key.
publicKeyToBytes :: SLHDSAPublicKey -> ByteString
publicKeyToBytes (SLHDSAPublicKey _ bs) = bs

-- | Generate a random SLH-DSA key pair. Returns @(publicKey, privateKey)@.
-- The private key is backed by 'SecureBytes' and zeroized on finalization.
generateKeyPair :: SLHDSAVariant -> IO (SLHDSAPublicKey, SecureBytes)
generateKeyPair variant = mask_ $ do
  let pubLen  = publicKeyBytes variant
      privLen = privateKeyBytes variant
  pubFPtr  <- BSI.mallocByteString pubLen
  privSB <- createSecureBytes privLen $ \privPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      case variant of
        SHA2_128S  -> c_SLHDSA_SHA2_128S_generate_key (castPtr pubPtr) privPtr
        SHAKE_256F -> c_SLHDSA_SHAKE_256F_generate_key (castPtr pubPtr) privPtr
  return (SLHDSAPublicKey variant (BSI.BS pubFPtr pubLen), privSB)

-- | Sign a message with an SLH-DSA private key.
--
-- @sign variant privateKey message context@ returns the signature, or an
-- error if the context is longer than 255 bytes or the private key has
-- the wrong length.
--
-- In 'IO': BoringSSL implements FIPS 205 __randomized__ signing, so each
-- call produces a different signature for the same inputs. Signing is
-- very slow by design.
sign :: SLHDSAVariant -> SecureBytes -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
sign variant privKey msg ctx
  | secureBytesLength privKey /= privateKeyBytes variant =
      return (Left (InvalidInput ("SLHDSA.sign: expected "
        ++ show (privateKeyBytes variant) ++ "-byte private key, got "
        ++ show (secureBytesLength privKey))))
  | BS.length ctx > 255 =
      return (Left (InvalidInput "SLHDSA.sign: context must be at most 255 bytes"))
  | otherwise = do
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

-- | Verify an SLH-DSA signature.
--
-- @verify pub msg sig context@ — pure and fail-closed: 'False' covers
-- invalid signatures and any malformed input. The variant travels with
-- the public key.
verify :: SLHDSAPublicKey -> ByteString -> ByteString -> ByteString -> Bool
verify (SLHDSAPublicKey variant pubKey) msg sig ctx = unsafePerformIO $
  withByteString sig $ \sigPtr sigLen ->
    withByteString pubKey $ \pubPtr _ ->
      withByteString msg $ \msgPtr msgLen ->
        withByteString ctx $ \ctxPtr ctxLen -> do
          rc <- case variant of
            SHA2_128S  -> c_SLHDSA_SHA2_128S_verify
                            sigPtr sigLen pubPtr msgPtr msgLen ctxPtr ctxLen
            SHAKE_256F -> c_SLHDSA_SHAKE_256F_verify
                            sigPtr sigLen pubPtr msgPtr msgLen ctxPtr ctxLen
          return (rc == 1)
{-# NOINLINE verify #-}
