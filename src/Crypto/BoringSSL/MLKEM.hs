-- | Post-quantum ML-KEM (FIPS 203, formerly Kyber) key encapsulation.
--
-- Provides ML-KEM-768 and ML-KEM-1024 for post-quantum key exchange.
-- ML-KEM-768 is recommended for most uses; ML-KEM-1024 offers a higher
-- security margin. For a hybrid with X25519, see "Crypto.BoringSSL.XWing".
--
-- __Implicit rejection (FIPS 203)__: 'decapsulate' never fails on a
-- well-formed-length ciphertext. A tampered or wrong ciphertext yields
-- 'Right' with a deterministic /pseudo-random/ secret that will not match
-- the encapsulator's — the mismatch surfaces later (e.g. as an AEAD
-- authentication failure), never at decapsulation. This is by design; do
-- not test for tampering by expecting 'Left'.
module Crypto.BoringSSL.MLKEM
  ( MLKEMVariant(..)
  , MLKEMPublicKey
  , MLKEMPrivateKey
  , generateKeyPair
  , encapsulate
  , encapsulatePublic
  , decapsulate
    -- * Public key serialization
  , publicKeyFromBytes
  , publicKeyToBytes
    -- * Constants
  , publicKeyBytes
  , ciphertextBytes
  , sharedSecretBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Control.Exception (mask_)
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.CBS
import Crypto.BoringSSL.Internal.FFI.MLKEM
import Crypto.BoringSSL.Internal.SecureBytes

-- | ML-KEM variant selection.
data MLKEMVariant = MLKEM768 | MLKEM1024
  deriving (Eq, Show)

-- | An ML-KEM public key: validated, variant-tagged encoded bytes.
-- Build one with 'publicKeyFromBytes' or 'generateKeyPair'.
data MLKEMPublicKey = MLKEMPublicKey !MLKEMVariant !ByteString
  deriving (Eq)

instance Show MLKEMPublicKey where
  show (MLKEMPublicKey v _) = "MLKEMPublicKey " ++ show v

-- | An opaque ML-KEM private key. Contains variant information and
-- the private key struct data managed by a ForeignPtr in secure memory.
data MLKEMPrivateKey = MLKEMPrivateKey !MLKEMVariant !(ForeignPtr ())

instance Show MLKEMPrivateKey where
  show (MLKEMPrivateKey v _) = "MLKEMPrivateKey " ++ show v ++ " <redacted>"

-- | Query the encoded public key size for a variant.
publicKeyBytes :: MLKEMVariant -> Int
publicKeyBytes MLKEM768  = mlkem768PublicKeyBytes
publicKeyBytes MLKEM1024 = mlkem1024PublicKeyBytes

-- | Query the ciphertext size for a variant.
ciphertextBytes :: MLKEMVariant -> Int
ciphertextBytes MLKEM768  = mlkem768CiphertextBytes
ciphertextBytes MLKEM1024 = mlkem1024CiphertextBytes

-- | The shared secret size in bytes (32 for both variants).
sharedSecretBytes :: Int
sharedSecretBytes = mlkemSharedSecretBytes

-- | Parse (with a pk-struct callback) the encoded public key. Assumes the
-- length was already validated. Returns Nothing if parsing rejects the
-- bytes. The callback receives an untyped pointer to the parsed struct;
-- per-variant callers cast it to the right phantom type.
withParsedPublicKey :: MLKEMVariant -> ByteString -> (Ptr () -> IO a) -> IO (Maybe a)
withParsedPublicKey variant encoded f = do
  let pkStructSize = case variant of
        MLKEM768  -> mlkem768PublicKeySize
        MLKEM1024 -> mlkem1024PublicKeySize
  allocaBytes pkStructSize $ \pkStructPtr ->
    withByteString encoded $ \pkBytesPtr pkBytesLen ->
      allocaBytes c_bssl_CBS_size $ \cbsPtr -> do
        c_bssl_CBS_init cbsPtr (castPtr pkBytesPtr) pkBytesLen
        rc <- case variant of
          MLKEM768  -> c_MLKEM768_parse_public_key (castPtr pkStructPtr) (castPtr cbsPtr)
          MLKEM1024 -> c_MLKEM1024_parse_public_key (castPtr pkStructPtr) (castPtr cbsPtr)
        if rc /= 1
          then return Nothing
          else Just <$> f (castPtr pkStructPtr)

-- | Validate and wrap an encoded ML-KEM public key. Checks both the
-- length and that the bytes parse as a valid key. Pure.
publicKeyFromBytes :: MLKEMVariant -> ByteString -> Either CryptoError MLKEMPublicKey
publicKeyFromBytes variant bs
  | BS.length bs /= publicKeyBytes variant =
      Left (InvalidInput ("MLKEM.publicKeyFromBytes: expected "
        ++ show (publicKeyBytes variant) ++ " bytes, got " ++ show (BS.length bs)))
  | otherwise = unsafePerformIO $ do
      parsed <- withParsedPublicKey variant bs (\_ -> return ())
      case parsed of
        Nothing -> return (Left (DecodeError "MLKEM.publicKeyFromBytes: invalid public key encoding"))
        Just () -> return (Right (MLKEMPublicKey variant bs))
{-# NOINLINE publicKeyFromBytes #-}

-- | The encoded bytes of a public key.
publicKeyToBytes :: MLKEMPublicKey -> ByteString
publicKeyToBytes (MLKEMPublicKey _ bs) = bs

-- | Generate a random ML-KEM key pair.
generateKeyPair :: MLKEMVariant -> IO (MLKEMPublicKey, MLKEMPrivateKey)
generateKeyPair variant = mask_ $ do
  let (pkSize, skSize) = case variant of
        MLKEM768  -> (mlkem768PublicKeyBytes, mlkem768PrivateKeySize)
        MLKEM1024 -> (mlkem1024PublicKeyBytes, mlkem1024PrivateKeySize)
  pubFPtr <- BSI.mallocByteString pkSize
  skFPtr <- mallocSecureForeignPtr skSize
  withForeignPtr pubFPtr $ \pubPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      case variant of
        MLKEM768  -> c_MLKEM768_generate_key (castPtr pubPtr) nullPtr (castPtr skPtr)
        MLKEM1024 -> c_MLKEM1024_generate_key (castPtr pubPtr) nullPtr (castPtr skPtr)
  return ( MLKEMPublicKey variant (BSI.BS pubFPtr pkSize)
         , MLKEMPrivateKey variant skFPtr )

-- | Encapsulate a shared secret against your /own/ private key (the
-- public key is derived internally). This is only useful for testing or
-- self-encryption; the standard KEM flow against a peer's public key is
-- 'encapsulatePublic'. Returns @(ciphertext, sharedSecret)@.
encapsulate :: MLKEMPrivateKey -> IO (ByteString, SecureBytes)
encapsulate (MLKEMPrivateKey variant skFPtr) = mask_ $ do
  let (ctSize, pkStructSize) = case variant of
        MLKEM768  -> (mlkem768CiphertextBytes, mlkem768PublicKeySize)
        MLKEM1024 -> (mlkem1024CiphertextBytes, mlkem1024PublicKeySize)
  ctFPtr <- BSI.mallocByteString ctSize
  ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
  allocaBytes pkStructSize $ \pkStructPtr ->
    withForeignPtr skFPtr $ \skPtr ->
      withForeignPtr ctFPtr $ \ctPtr ->
        withSecureBytes ssSB $ \ssPtr _ ->
          case variant of
            MLKEM768 -> do
              c_MLKEM768_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
              c_MLKEM768_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
            MLKEM1024 -> do
              c_MLKEM1024_public_from_private (castPtr pkStructPtr) (castPtr skPtr)
              c_MLKEM1024_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
  return (BSI.BS ctFPtr ctSize, ssSB)

-- | Encapsulate a shared secret to a peer's public key — the standard
-- KEM operation. In 'IO' because encapsulation is randomized. Returns
-- @(ciphertext, sharedSecret)@; the shared secret lives in
-- 'SecureBytes'.
encapsulatePublic :: MLKEMPublicKey -> IO (ByteString, SecureBytes)
encapsulatePublic (MLKEMPublicKey variant encoded) = do
  let ctSize = ciphertextBytes variant
  ctFPtr <- BSI.mallocByteString ctSize
  ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
  parsed <- withParsedPublicKey variant encoded $ \pkStructPtr ->
    withForeignPtr ctFPtr $ \ctPtr ->
      withSecureBytes ssSB $ \ssPtr _ ->
        case variant of
          MLKEM768  -> c_MLKEM768_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
          MLKEM1024 -> c_MLKEM1024_encap (castPtr ctPtr) ssPtr (castPtr pkStructPtr)
  case parsed of
    -- Unreachable: the key was validated by publicKeyFromBytes/keygen.
    Nothing -> errorWithoutStackTrace "MLKEM.encapsulatePublic: validated key failed to parse"
    Just _  -> return (BSI.BS ctFPtr ctSize, ssSB)

-- | Decapsulate a shared secret from a ciphertext using a private key.
-- Pure: decapsulation is deterministic.
--
-- __Remember implicit rejection__ (module header): a tampered ciphertext
-- of the correct length returns 'Right' with a pseudo-random secret, not
-- 'Left'. 'Left' occurs only for a wrong-length ciphertext.
decapsulate :: MLKEMPrivateKey -> ByteString -> Either CryptoError SecureBytes
decapsulate (MLKEMPrivateKey variant skFPtr) ciphertext
  | BS.length ciphertext /= ciphertextBytes variant =
      Left (InvalidInput ("MLKEM.decapsulate: expected "
        ++ show (ciphertextBytes variant) ++ "-byte ciphertext, got "
        ++ show (BS.length ciphertext)))
  | otherwise = unsafePerformIO $ do
      ssSB <- createSecureBytes mlkemSharedSecretBytes $ \_ -> return ()
      rc <- withForeignPtr skFPtr $ \skPtr ->
        withByteString ciphertext $ \ctPtr ctLen ->
          withSecureBytes ssSB $ \ssPtr _ ->
            case variant of
              MLKEM768  -> c_MLKEM768_decap ssPtr ctPtr ctLen (castPtr skPtr)
              MLKEM1024 -> c_MLKEM1024_decap ssPtr ctPtr ctLen (castPtr skPtr)
      if rc == 1
        then return (Right ssSB)
        else return (Left (OperationFailed "MLKEM.decapsulate: decapsulation failed"))
{-# NOINLINE decapsulate #-}
