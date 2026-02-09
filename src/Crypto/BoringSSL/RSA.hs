-- | RSA encryption and digital signatures.
--
-- Supports PKCS#1 v1.5 and PSS signing, and OAEP encryption.
-- Key serialization uses DER-encoded PKCS#1 format.
module Crypto.BoringSSL.RSA
  ( -- * Key types
    RSAKeyPair(..)
  , RSAPublicKey(..)
    -- * Key generation
  , generateRSAKeyPair
    -- * Serialization
  , publicKeyToBytes
  , publicKeyFromBytes
  , privateKeyToBytes
  , privateKeyFromBytes
    -- * Properties
  , rsaBits
  , rsaSize
    -- * PKCS#1 v1.5 signing
  , rsaSign
  , rsaVerify
    -- * PSS signing
  , rsaSignPSS
  , rsaVerifyPSS
    -- * OAEP encryption
  , rsaEncrypt
  , rsaDecrypt
    -- * Error type
  , BoringSSLError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_, mask, onException)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.FFI.RSA
import Crypto.BoringSSL.Internal.FFI.ECKey (c_BN_new, c_BN_free, c_BN_set_word)

-- | An RSA key pair (private + public).
newtype RSAKeyPair = RSAKeyPair (ForeignPtr RSA_C)

-- | An RSA public key only.
newtype RSAPublicKey = RSAPublicKey (ForeignPtr RSA_C)

-- | RSA_PKCS1_AEP_PADDING = 4
rsaPKCS1OAEPPadding :: CInt
rsaPKCS1OAEPPadding = 4

-- | Generate a new RSA key pair. The key size must be at least 2048 bits.
generateRSAKeyPair :: Int -> IO (Either BoringSSLError RSAKeyPair)
generateRSAKeyPair bits
  | bits < 2048 = return (Left (BoringSSLError 0 "generateRSAKeyPair: key size must be at least 2048 bits"))
  | otherwise = mask $ \restore -> do
  rsa <- c_RSA_new
  if rsa == nullPtr
    then return (Left (BoringSSLError 0 "generateRSAKeyPair: RSA_new failed"))
    else do
      e <- c_BN_new
      if e == nullPtr
        then do
          c_RSA_free rsa
          return (Left (BoringSSLError 0 "generateRSAKeyPair: BN_new failed"))
        else do
          _ <- c_BN_set_word e 65537
          rc <- restore (c_RSA_generate_key_ex rsa (fromIntegral bits) e nullPtr)
                  `onException` (c_BN_free e >> c_RSA_free rsa)
          c_BN_free e
          if rc /= 1
            then do
              c_RSA_free rsa
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "generateRSAKeyPair: RSA_generate_key_ex failed") id merr))
            else do
              fptr <- newForeignPtr c_RSA_free_funptr rsa
              return (Right (RSAKeyPair fptr))

-- | Serialize the public key to DER-encoded PKCS#1 format.
publicKeyToBytes :: RSAKeyPair -> IO (Either BoringSSLError ByteString)
publicKeyToBytes (RSAKeyPair fptr) =
  withForeignPtr fptr $ \rsa ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_RSA_public_key_to_bytes outPtrPtr outLenPtr rsa
        if rc /= 1
          then do
            merr <- getBoringSSLError
            return (Left (maybe (BoringSSLError 0 "publicKeyToBytes: RSA_public_key_to_bytes failed") id merr))
          else Right <$> packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a public key from DER-encoded PKCS#1 format.
publicKeyFromBytes :: ByteString -> IO (Either BoringSSLError RSAPublicKey)
publicKeyFromBytes bs =
  withByteString bs $ \ptr len -> mask_ $ do
    rsa <- c_RSA_public_key_from_bytes ptr len
    if rsa == nullPtr
      then do
        merr <- getBoringSSLError
        return (Left (maybe (BoringSSLError 0 "publicKeyFromBytes: RSA_public_key_from_bytes failed") id merr))
      else do
        fptr <- newForeignPtr c_RSA_free_funptr rsa
        return (Right (RSAPublicKey fptr))

-- | Serialize the private key to DER-encoded PKCS#1 format.
privateKeyToBytes :: RSAKeyPair -> IO (Either BoringSSLError ByteString)
privateKeyToBytes (RSAKeyPair fptr) =
  withForeignPtr fptr $ \rsa ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsa
        if rc /= 1
          then do
            merr <- getBoringSSLError
            return (Left (maybe (BoringSSLError 0 "privateKeyToBytes: RSA_private_key_to_bytes failed") id merr))
          else Right <$> packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a private key from DER-encoded PKCS#1 format.
privateKeyFromBytes :: ByteString -> IO (Either BoringSSLError RSAKeyPair)
privateKeyFromBytes bs =
  withByteString bs $ \ptr len -> mask_ $ do
    rsa <- c_RSA_private_key_from_bytes ptr len
    if rsa == nullPtr
      then do
        merr <- getBoringSSLError
        return (Left (maybe (BoringSSLError 0 "privateKeyFromBytes: RSA_private_key_from_bytes failed") id merr))
      else do
        fptr <- newForeignPtr c_RSA_free_funptr rsa
        return (Right (RSAKeyPair fptr))

-- | Get the RSA key size in bits.
rsaBits :: RSAKeyPair -> IO Int
rsaBits (RSAKeyPair fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_bits rsa

-- | Get the RSA modulus size in bytes.
rsaSize :: RSAKeyPair -> IO Int
rsaSize (RSAKeyPair fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_size rsa

-- | PKCS#1 v1.5 sign a pre-hashed digest.
rsaSign :: RSAKeyPair -> Algorithm -> ByteString -> IO (Either BoringSSLError ByteString)
rsaSign (RSAKeyPair fptr) algo digest =
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    outFPtr <- BSI.mallocByteString modSize
    result <- withForeignPtr outFPtr $ \outPtr ->
      withByteString digest $ \digestPtr digestLen ->
        alloca $ \outLenPtr -> do
          rc <- c_RSA_sign (ID.algorithmNID algo) digestPtr digestLen
                  (castPtr outPtr) outLenPtr rsa
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "rsaSign: RSA_sign failed") id merr))
            else do
              actualLen <- peek outLenPtr
              return (Right (fromIntegral actualLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS outFPtr len))

-- | PKCS#1 v1.5 verify a signature on a pre-hashed digest.
rsaVerify :: RSAPublicKey -> Algorithm -> ByteString -> ByteString -> IO Bool
rsaVerify (RSAPublicKey fptr) algo digest sig =
  withForeignPtr fptr $ \rsa ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        rc <- c_RSA_verify (ID.algorithmNID algo) digestPtr digestLen sigPtr sigLen rsa
        return (rc == 1)

-- | RSA-PSS sign a pre-hashed digest. Uses the same hash for MGF1
-- and salt length equal to the digest size.
rsaSignPSS :: RSAKeyPair -> Algorithm -> ByteString -> IO (Either BoringSSLError ByteString)
rsaSignPSS (RSAKeyPair fptr) algo digest =
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    outFPtr <- BSI.mallocByteString modSize
    result <- withForeignPtr outFPtr $ \outPtr ->
      withByteString digest $ \digestPtr digestLen ->
        alloca $ \outLenPtr -> do
          let md = ID.evpMD algo
              saltLen = fromIntegral (ID.digestSize algo)
          rc <- c_RSA_sign_pss_mgf1 rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
                  digestPtr digestLen md md saltLen
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "rsaSignPSS: failed") id merr))
            else do
              actualLen <- peek outLenPtr
              return (Right (fromIntegral actualLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS outFPtr len))

-- | RSA-PSS verify a signature on a pre-hashed digest.
rsaVerifyPSS :: RSAPublicKey -> Algorithm -> ByteString -> ByteString -> IO Bool
rsaVerifyPSS (RSAPublicKey fptr) algo digest sig =
  withForeignPtr fptr $ \rsa ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        let md = ID.evpMD algo
            saltLen = fromIntegral (ID.digestSize algo)
        rc <- c_RSA_verify_pss_mgf1 rsa digestPtr digestLen md md saltLen sigPtr sigLen
        return (rc == 1)

-- | RSA-OAEP encrypt plaintext with a public key.
rsaEncrypt :: RSAPublicKey -> ByteString -> IO (Either BoringSSLError ByteString)
rsaEncrypt (RSAPublicKey fptr) plaintext =
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    outFPtr <- BSI.mallocByteString modSize
    result <- withForeignPtr outFPtr $ \outPtr ->
      withByteString plaintext $ \inPtr inLen ->
        alloca $ \outLenPtr -> do
          rc <- c_RSA_encrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
                  inPtr inLen rsaPKCS1OAEPPadding
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "rsaEncrypt: failed") id merr))
            else do
              actualLen <- peek outLenPtr
              return (Right (fromIntegral actualLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS outFPtr len))

-- | RSA-OAEP decrypt ciphertext with a private key.
rsaDecrypt :: RSAKeyPair -> ByteString -> IO (Either BoringSSLError ByteString)
rsaDecrypt (RSAKeyPair fptr) ciphertext =
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    outFPtr <- BSI.mallocByteString modSize
    result <- withForeignPtr outFPtr $ \outPtr ->
      withByteString ciphertext $ \inPtr inLen ->
        alloca $ \outLenPtr -> do
          rc <- c_RSA_decrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
                  inPtr inLen rsaPKCS1OAEPPadding
          if rc /= 1
            then do
              merr <- getBoringSSLError
              return (Left (maybe (BoringSSLError 0 "rsaDecrypt: failed") id merr))
            else do
              actualLen <- peek outLenPtr
              return (Right (fromIntegral actualLen))
    case result of
      Left err  -> return (Left err)
      Right len -> return (Right (BSI.BS outFPtr len))
