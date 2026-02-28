-- | Post-quantum ML-DSA (Dilithium) digital signature scheme.
--
-- Provides ML-DSA-44, ML-DSA-65, and ML-DSA-87 for post-quantum digital
-- signatures. ML-DSA-65 is recommended for most uses. ML-DSA-44 offers
-- smaller keys and signatures at a lower security level. ML-DSA-87 is
-- available for CNSA 2.0 compliance.
module Crypto.BoringSSL.MLDSA
  ( -- * Variant selection
    MLDSAVariant(..)
    -- * Key types
  , MLDSAPrivateKey
  , MLDSAPublicKey
    -- * Key generation
  , generateKeyPair
  , privateKeyFromSeed
  , publicKeyFromPrivate
  , publicKeyFromBytes
    -- * Signing and verification
  , sign
  , verify
    -- * Constants
  , publicKeyBytes
  , signatureBytes
  , seedBytes
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Control.Exception (mask_)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.CBS
import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_cleanse)
import Crypto.BoringSSL.Internal.FFI.MLDSA
import Crypto.BoringSSL.Internal.SecureBytes

-- | ML-DSA variant selection.
data MLDSAVariant = MLDSA44 | MLDSA65 | MLDSA87
  deriving (Eq, Show)

-- | An opaque ML-DSA private key. Contains variant information and
-- the private key struct data managed by a ForeignPtr.
data MLDSAPrivateKey = MLDSAPrivateKey !MLDSAVariant !(ForeignPtr ())

instance Show MLDSAPrivateKey where
  show (MLDSAPrivateKey v _) = "MLDSAPrivateKey " ++ show v ++ " <redacted>"

-- | An opaque ML-DSA public key. Contains variant information and
-- the public key struct data managed by a ForeignPtr.
data MLDSAPublicKey = MLDSAPublicKey !MLDSAVariant !(ForeignPtr ())

instance Show MLDSAPublicKey where
  show (MLDSAPublicKey v _) = "MLDSAPublicKey " ++ show v

-- | Query the encoded public key size in bytes for a variant.
publicKeyBytes :: MLDSAVariant -> Int
publicKeyBytes MLDSA44 = mldsa44PublicKeyBytes
publicKeyBytes MLDSA65 = mldsa65PublicKeyBytes
publicKeyBytes MLDSA87 = mldsa87PublicKeyBytes

-- | Query the signature size in bytes for a variant.
signatureBytes :: MLDSAVariant -> Int
signatureBytes MLDSA44 = mldsa44SignatureBytes
signatureBytes MLDSA65 = mldsa65SignatureBytes
signatureBytes MLDSA87 = mldsa87SignatureBytes

-- | The seed size in bytes (32 for all variants).
seedBytes :: Int
seedBytes = mldsaSeedBytes

-- Internal: private key struct size for a variant.
privateKeySize :: MLDSAVariant -> Int
privateKeySize MLDSA44 = mldsa44PrivateKeySize
privateKeySize MLDSA65 = mldsa65PrivateKeySize
privateKeySize MLDSA87 = mldsa87PrivateKeySize

-- Internal: public key struct size for a variant.
publicKeySize :: MLDSAVariant -> Int
publicKeySize MLDSA44 = mldsa44PublicKeySize
publicKeySize MLDSA65 = mldsa65PublicKeySize
publicKeySize MLDSA87 = mldsa87PublicKeySize

-- | Generate a random ML-DSA key pair.
-- Returns @(encodedPublicKey, seed, privateKey)@ where @seed@ is the
-- 32-byte seed that can be used with 'privateKeyFromSeed' to regenerate
-- the private key. The seed is returned as 'SecureBytes' and zeroized on
-- finalization.
generateKeyPair :: MLDSAVariant -> IO (Either CryptoError (ByteString, SecureBytes, MLDSAPrivateKey))
generateKeyPair variant = withBoundThread $ mask_ $ do
  let pkSize = publicKeyBytes variant
      skSize = privateKeySize variant
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocSecureForeignPtr skSize
  allocaBytes mldsaSeedBytes $ \seedPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      withForeignPtr skFPtr $ \skPtr -> do
        clearBoringSSLError
        rc <- case variant of
          MLDSA44 -> c_MLDSA44_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
          MLDSA65 -> c_MLDSA65_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
          MLDSA87 -> c_MLDSA87_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
        if rc /= 1
          then do
            c_OPENSSL_cleanse (castPtr seedPtr) (fromIntegral mldsaSeedBytes)
            Left . fromMaybe (OperationFailed "MLDSA_generate_key failed") <$> getBoringSSLError
          else do
            seedSB <- createSecureBytes mldsaSeedBytes $ \dstPtr ->
              copyBytes (castPtr dstPtr) (castPtr seedPtr) mldsaSeedBytes
            c_OPENSSL_cleanse (castPtr seedPtr) (fromIntegral mldsaSeedBytes)
            return (Right (BSI.BS pubFPtr pkSize, seedSB, MLDSAPrivateKey variant skFPtr))

-- | Regenerate a private key from a seed value that was produced by
-- 'generateKeyPair'. The seed must be exactly 32 bytes.
-- Accepts 'SecureBytes' to preserve zeroization guarantees.
privateKeyFromSeed :: MLDSAVariant -> SecureBytes -> Either CryptoError MLDSAPrivateKey
privateKeyFromSeed variant seed
  | secureBytesLength seed /= mldsaSeedBytes =
      Left (InvalidInput "privateKeyFromSeed: seed must be 32 bytes")
  | otherwise = unsafePerformIO $ mask_ $ do
      let skSize = privateKeySize variant
      skFPtr <- mallocSecureForeignPtr skSize
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withSecureBytes seed $ \seedPtr seedLen ->
          case variant of
            MLDSA44 -> c_MLDSA44_private_key_from_seed (castPtr skPtr) seedPtr seedLen
            MLDSA65 -> c_MLDSA65_private_key_from_seed (castPtr skPtr) seedPtr seedLen
            MLDSA87 -> c_MLDSA87_private_key_from_seed (castPtr skPtr) seedPtr seedLen
      if rc == 1
        then return (Right (MLDSAPrivateKey variant skFPtr))
        else return (Left (OperationFailed "MLDSA_private_key_from_seed failed"))
{-# NOINLINE privateKeyFromSeed #-}

-- | Derive the public key struct from a private key.
publicKeyFromPrivate :: MLDSAPrivateKey -> Either CryptoError MLDSAPublicKey
publicKeyFromPrivate (MLDSAPrivateKey variant skFPtr) = unsafePerformIO $ do
  let pkSize = publicKeySize variant
  pkFPtr <- mallocForeignPtrBytes pkSize
  rc <- withForeignPtr pkFPtr $ \pkPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      case variant of
        MLDSA44 -> c_MLDSA44_public_from_private (castPtr pkPtr) (castPtr skPtr)
        MLDSA65 -> c_MLDSA65_public_from_private (castPtr pkPtr) (castPtr skPtr)
        MLDSA87 -> c_MLDSA87_public_from_private (castPtr pkPtr) (castPtr skPtr)
  if rc /= 1
    then return (Left (OperationFailed "MLDSA_public_from_private failed"))
    else return (Right (MLDSAPublicKey variant pkFPtr))
{-# NOINLINE publicKeyFromPrivate #-}

-- | Parse a public key from its encoded byte representation.
-- The ByteString must be exactly 'publicKeyBytes' for the given variant.
publicKeyFromBytes :: MLDSAVariant -> ByteString -> Either CryptoError MLDSAPublicKey
publicKeyFromBytes variant bs
  | BS.length bs /= publicKeyBytes variant =
      Left (InvalidInput "publicKeyFromBytes: incorrect length")
  | otherwise = unsafePerformIO $ do
      let pkSize = publicKeySize variant
      pkFPtr <- mallocForeignPtrBytes pkSize
      rc <- withForeignPtr pkFPtr $ \pkPtr ->
        withByteString bs $ \dataPtr dataLen ->
          allocaBytes c_bssl_CBS_size $ \cbsPtr -> do
            c_bssl_CBS_init cbsPtr (castPtr dataPtr) dataLen
            case variant of
              MLDSA44 -> c_MLDSA44_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
              MLDSA65 -> c_MLDSA65_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
              MLDSA87 -> c_MLDSA87_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
      if rc == 1
        then return (Right (MLDSAPublicKey variant pkFPtr))
        else return (Left (DecodeError "MLDSA_parse_public_key failed"))
{-# NOINLINE publicKeyFromBytes #-}

-- | Sign a message with an ML-DSA private key.
-- Takes a private key, message, and context string.
-- The @context@ parameter provides domain separation per FIPS 204;
-- pass an empty 'ByteString' for general-purpose use. The same context
-- must be supplied when verifying the signature.
sign :: MLDSAPrivateKey -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
sign (MLDSAPrivateKey variant skFPtr) msg context = withBoundThread $ do
  let sigSize = signatureBytes variant
  sigFPtr <- BSI.mallocByteString sigSize
  clearBoringSSLError
  rc <- withForeignPtr skFPtr $ \skPtr ->
    withByteString msg $ \msgPtr msgLen ->
      withByteString context $ \ctxPtr ctxLen ->
        withForeignPtr sigFPtr $ \sigPtr ->
          case variant of
            MLDSA44 -> c_MLDSA44_sign (castPtr sigPtr) (castPtr skPtr)
                         msgPtr msgLen ctxPtr ctxLen
            MLDSA65 -> c_MLDSA65_sign (castPtr sigPtr) (castPtr skPtr)
                         msgPtr msgLen ctxPtr ctxLen
            MLDSA87 -> c_MLDSA87_sign (castPtr sigPtr) (castPtr skPtr)
                         msgPtr msgLen ctxPtr ctxLen
  if rc == 1
    then return (Right (BSI.BS sigFPtr sigSize))
    else do
      Left . fromMaybe (OperationFailed "MLDSA_sign failed") <$> getBoringSSLError

-- | Verify an ML-DSA signature (pure).
-- Takes the public key, signature, message, and context.
-- The @context@ must match the value used during signing.
-- Returns True if the signature is valid.
verify :: MLDSAPublicKey -> ByteString -> ByteString -> ByteString -> Bool
verify (MLDSAPublicKey variant pkFPtr) sig msg context = unsafePerformIO $
  withForeignPtr pkFPtr $ \pkPtr ->
    withByteString sig $ \sigPtr sigLen ->
      withByteString msg $ \msgPtr msgLen ->
        withByteString context $ \ctxPtr ctxLen -> do
          rc <- case variant of
            MLDSA44 -> c_MLDSA44_verify (castPtr pkPtr)
                         sigPtr sigLen msgPtr msgLen ctxPtr ctxLen
            MLDSA65 -> c_MLDSA65_verify (castPtr pkPtr)
                         sigPtr sigLen msgPtr msgLen ctxPtr ctxLen
            MLDSA87 -> c_MLDSA87_verify (castPtr pkPtr)
                         sigPtr sigLen msgPtr msgLen ctxPtr ctxLen
          return (rc == 1)
{-# NOINLINE verify #-}
