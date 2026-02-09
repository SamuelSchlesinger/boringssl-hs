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
    -- * Error type
  , BoringSSLError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.MLDSA

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

-- Internal: size of a CBS struct (pointer + size_t).
cbsSize :: Int
cbsSize = sizeOf (undefined :: Ptr ()) + sizeOf (undefined :: CSize)

-- | Generate a random ML-DSA key pair.
-- Returns @(encodedPublicKey, seed, privateKey)@ where @seed@ is the
-- 32-byte seed that can be used with 'privateKeyFromSeed' to regenerate
-- the private key.
generateKeyPair :: MLDSAVariant -> IO (Either BoringSSLError (ByteString, ByteString, MLDSAPrivateKey))
generateKeyPair variant = do
  let pkSize = publicKeyBytes variant
      skSize = privateKeySize variant
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocForeignPtrBytes skSize
  allocaBytes mldsaSeedBytes $ \seedPtr ->
    withForeignPtr pubFPtr $ \pubPtr ->
      withForeignPtr skFPtr $ \skPtr -> do
        rc <- case variant of
          MLDSA44 -> c_MLDSA44_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
          MLDSA65 -> c_MLDSA65_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
          MLDSA87 -> c_MLDSA87_generate_key (castPtr pubPtr) seedPtr (castPtr skPtr)
        if rc /= 1
          then do
            merr <- getBoringSSLError
            return (Left (maybe (BoringSSLError 0 "MLDSA_generate_key failed") id merr))
          else do
            seedBs <- BS.packCStringLen (castPtr seedPtr, mldsaSeedBytes)
            return (Right (BSI.BS pubFPtr pkSize, seedBs, MLDSAPrivateKey variant skFPtr))

-- | Regenerate a private key from a seed value that was produced by
-- 'generateKeyPair'. The seed must be exactly 32 bytes.
privateKeyFromSeed :: MLDSAVariant -> ByteString -> Either BoringSSLError MLDSAPrivateKey
privateKeyFromSeed variant seed
  | BS.length seed /= mldsaSeedBytes =
      Left (BoringSSLError 0 "privateKeyFromSeed: seed must be 32 bytes")
  | otherwise = unsafePerformIO $ do
      let skSize = privateKeySize variant
      skFPtr <- mallocForeignPtrBytes skSize
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString seed $ \seedPtr seedLen ->
          case variant of
            MLDSA44 -> c_MLDSA44_private_key_from_seed (castPtr skPtr) seedPtr seedLen
            MLDSA65 -> c_MLDSA65_private_key_from_seed (castPtr skPtr) seedPtr seedLen
            MLDSA87 -> c_MLDSA87_private_key_from_seed (castPtr skPtr) seedPtr seedLen
      if rc == 1
        then return (Right (MLDSAPrivateKey variant skFPtr))
        else return (Left (BoringSSLError 0 "MLDSA_private_key_from_seed failed"))
{-# NOINLINE privateKeyFromSeed #-}

-- | Derive the public key struct from a private key.
publicKeyFromPrivate :: MLDSAPrivateKey -> Either BoringSSLError MLDSAPublicKey
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
    then return (Left (BoringSSLError 0 "MLDSA_public_from_private failed"))
    else return (Right (MLDSAPublicKey variant pkFPtr))
{-# NOINLINE publicKeyFromPrivate #-}

-- | Parse a public key from its encoded byte representation.
-- The ByteString must be exactly 'publicKeyBytes' for the given variant.
publicKeyFromBytes :: MLDSAVariant -> ByteString -> Either BoringSSLError MLDSAPublicKey
publicKeyFromBytes variant bs
  | BS.length bs /= publicKeyBytes variant =
      Left (BoringSSLError 0 "publicKeyFromBytes: incorrect length")
  | otherwise = unsafePerformIO $ do
      let pkSize = publicKeySize variant
      pkFPtr <- mallocForeignPtrBytes pkSize
      rc <- withForeignPtr pkFPtr $ \pkPtr ->
        withByteString bs $ \dataPtr dataLen ->
          -- Allocate a CBS struct on the stack: { const uint8_t *data; size_t len; }
          allocaBytes cbsSize $ \cbsPtr -> do
            pokeByteOff cbsPtr 0 dataPtr
            pokeByteOff cbsPtr (sizeOf (undefined :: Ptr ())) (dataLen :: CSize)
            case variant of
              MLDSA44 -> c_MLDSA44_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
              MLDSA65 -> c_MLDSA65_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
              MLDSA87 -> c_MLDSA87_parse_public_key (castPtr pkPtr) (castPtr cbsPtr)
      if rc == 1
        then return (Right (MLDSAPublicKey variant pkFPtr))
        else return (Left (BoringSSLError 0 "MLDSA_parse_public_key failed"))
{-# NOINLINE publicKeyFromBytes #-}

-- | Sign a message with an ML-DSA private key.
-- Takes a private key, message, and context string.
sign :: MLDSAPrivateKey -> ByteString -> ByteString -> IO (Either BoringSSLError ByteString)
sign (MLDSAPrivateKey variant skFPtr) msg context = do
  let sigSize = signatureBytes variant
  sigFPtr <- BSI.mallocByteString sigSize
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
      merr <- getBoringSSLError
      return (Left (maybe (BoringSSLError 0 "MLDSA_sign failed") id merr))

-- | Verify an ML-DSA signature (pure).
-- Takes the public key, signature, message, and context.
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
