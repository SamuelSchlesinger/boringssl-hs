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
    -- * PKCS#1 v1.5 encryption
  , rsaEncryptPKCS1
  , rsaDecryptPKCS1
    -- * Public key properties
  , rsaPublicBits
  , rsaPublicSize
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask, onException)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.FFI.RSA
import Crypto.BoringSSL.Internal.FFI.ECKey (c_BN_new, c_BN_free, c_BN_set_word)

-- | An RSA key pair (private + public).
newtype RSAKeyPair = RSAKeyPair (ForeignPtr RSA_C)

-- | An RSA public key only.
newtype RSAPublicKey = RSAPublicKey (ForeignPtr RSA_C)

-- | RSA_PKCS1_OAEP_PADDING = 4
rsaPKCS1OAEPPadding :: CInt
rsaPKCS1OAEPPadding = 4

-- | RSA_PKCS1_PADDING = 1
rsaPKCS1Padding :: CInt
rsaPKCS1Padding = 1

-- | Generate a new RSA key pair. The key size must be at least 2048 bits.
generateRSAKeyPair :: Int -> IO (Either CryptoError RSAKeyPair)
generateRSAKeyPair bits
  | bits < 2048 = return (Left (InvalidInput "generateRSAKeyPair: key size must be at least 2048 bits"))
  | otherwise = withBoundThread $ mask $ \restore -> do
  rsa <- c_RSA_new
  if rsa == nullPtr
    then return (Left (AllocationFailure "generateRSAKeyPair: RSA_new failed"))
    else do
      e <- c_BN_new
      if e == nullPtr
        then do
          c_RSA_free rsa
          return (Left (AllocationFailure "generateRSAKeyPair: BN_new failed"))
        else do
          _ <- c_BN_set_word e 65537
          clearBoringSSLError
          rc <- restore (c_RSA_generate_key_ex rsa (fromIntegral bits) e nullPtr)
                  `onException` (c_BN_free e >> c_RSA_free rsa)
          c_BN_free e
          if rc /= 1
            then do
              c_RSA_free rsa
              Left . fromMaybe (OperationFailed "generateRSAKeyPair: RSA_generate_key_ex failed") <$> getBoringSSLError
            else do
              fptr <- newForeignPtr c_RSA_free_funptr rsa
              return (Right (RSAKeyPair fptr))

-- | Serialize the public key to DER-encoded PKCS#1 format.
publicKeyToBytes :: RSAKeyPair -> IO (Either CryptoError ByteString)
publicKeyToBytes (RSAKeyPair fptr) = withBoundThread $
  withForeignPtr fptr $ \rsa -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
      liftIO clearBoringSSLError
      rc <- liftIO $ c_RSA_public_key_to_bytes outPtrPtr outLenPtr rsa
      checkRCError "publicKeyToBytes: RSA_public_key_to_bytes failed" rc
      liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a public key from DER-encoded PKCS#1 format.
publicKeyFromBytes :: ByteString -> IO (Either CryptoError RSAPublicKey)
publicKeyFromBytes bs = withBoundThread $
  withByteString bs $ \ptr len -> runExceptT $ maskE_ $ do
    liftIO clearBoringSSLError
    rsa <- liftIO (c_RSA_public_key_from_bytes ptr len)
      >>= nonNull (OperationFailed "publicKeyFromBytes: RSA_public_key_from_bytes failed")
    fptr <- liftIO $ newForeignPtr c_RSA_free_funptr rsa
    return (RSAPublicKey fptr)

-- | Serialize the private key to DER-encoded PKCS#1 format.
privateKeyToBytes :: RSAKeyPair -> IO (Either CryptoError ByteString)
privateKeyToBytes (RSAKeyPair fptr) = withBoundThread $
  withForeignPtr fptr $ \rsa -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
      liftIO clearBoringSSLError
      rc <- liftIO $ c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsa
      checkRCError "privateKeyToBytes: RSA_private_key_to_bytes failed" rc
      liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a private key from DER-encoded PKCS#1 format.
privateKeyFromBytes :: ByteString -> IO (Either CryptoError RSAKeyPair)
privateKeyFromBytes bs = withBoundThread $
  withByteString bs $ \ptr len -> runExceptT $ maskE_ $ do
    liftIO clearBoringSSLError
    rsa <- liftIO (c_RSA_private_key_from_bytes ptr len)
      >>= nonNull (OperationFailed "privateKeyFromBytes: RSA_private_key_from_bytes failed")
    fptr <- liftIO $ newForeignPtr c_RSA_free_funptr rsa
    return (RSAKeyPair fptr)

-- | Get the RSA key size in bits.
rsaBits :: RSAKeyPair -> IO Int
rsaBits (RSAKeyPair fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_bits rsa

-- | Get the RSA modulus size in bytes.
rsaSize :: RSAKeyPair -> IO Int
rsaSize (RSAKeyPair fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_size rsa

-- | PKCS#1 v1.5 sign a pre-hashed digest.
-- Returns 'Left' if the algorithm has no NID (e.g. BLAKE2b256).
rsaSign :: RSAKeyPair -> Algorithm -> ByteString -> IO (Either CryptoError ByteString)
rsaSign _ algo _
  | Nothing <- ID.algorithmNID algo =
      return (Left (InvalidInput ("rsaSign: algorithm " ++ show algo ++ " has no NID and cannot be used with PKCS#1 v1.5")))
rsaSign (RSAKeyPair fptr) algo digest = withBoundThread $ do
  let nid = case ID.algorithmNID algo of
              Just n  -> n
              Nothing -> error "rsaSign: unreachable (algorithmNID already checked)"
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString digest $ \digestPtr digestLen -> runExceptT $ do
      outFPtr <- liftIO $ BSI.mallocByteString modSize
      allocaE $ \outLenPtr -> do
        liftIO clearBoringSSLError
        rc <- liftIO $ withForeignPtr outFPtr $ \outPtr ->
          c_RSA_sign nid digestPtr digestLen (castPtr outPtr) outLenPtr rsa
        checkRCError "rsaSign: RSA_sign failed" rc
        actualLen <- liftIO $ peek outLenPtr
        return (BSI.BS outFPtr (fromIntegral actualLen))

-- | PKCS#1 v1.5 verify a signature on a pre-hashed digest.
-- Returns @Left@ if the algorithm has no NID, or @Right False@ for invalid
-- signatures, or @Right True@ for valid signatures.
rsaVerify :: RSAPublicKey -> Algorithm -> ByteString -> ByteString -> IO (Either CryptoError Bool)
rsaVerify _ algo _ _
  | Nothing <- ID.algorithmNID algo =
      return (Left (InvalidInput ("rsaVerify: algorithm " ++ show algo ++ " has no NID and cannot be used with PKCS#1 v1.5")))
rsaVerify (RSAPublicKey fptr) algo digest sig = withBoundThread $ do
  let nid = case ID.algorithmNID algo of
              Just n  -> n
              Nothing -> error "rsaVerify: unreachable (algorithmNID already checked)"
  withForeignPtr fptr $ \rsa ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        clearBoringSSLError
        rc <- c_RSA_verify nid digestPtr digestLen sigPtr sigLen rsa
        checkVerifyRC rc "rsaVerify: internal error"

-- | RSA-PSS sign a pre-hashed digest. Uses the same hash for MGF1
-- and salt length equal to the digest size.
rsaSignPSS :: RSAKeyPair -> Algorithm -> ByteString -> IO (Either CryptoError ByteString)
rsaSignPSS (RSAKeyPair fptr) algo digest = withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString digest $ \digestPtr digestLen -> runExceptT $
      let md = ID.evpMD algo
          saltLen = fromIntegral (ID.digestSize algo)
      in withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_sign_pss_mgf1 rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            digestPtr digestLen md md saltLen)
        "rsaSignPSS: failed"

-- | RSA-PSS verify a signature on a pre-hashed digest.
-- Returns @Right True@ for valid, @Right False@ for invalid, or
-- @Left@ for internal errors.
rsaVerifyPSS :: RSAPublicKey -> Algorithm -> ByteString -> ByteString -> IO (Either CryptoError Bool)
rsaVerifyPSS (RSAPublicKey fptr) algo digest sig = withBoundThread $
  withForeignPtr fptr $ \rsa ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        let md = ID.evpMD algo
            saltLen = fromIntegral (ID.digestSize algo)
        clearBoringSSLError
        rc <- c_RSA_verify_pss_mgf1 rsa digestPtr digestLen md md saltLen sigPtr sigLen
        checkVerifyRC rc "rsaVerifyPSS: internal error"

-- | RSA-OAEP encrypt plaintext with a public key.
rsaEncrypt :: RSAPublicKey -> ByteString -> IO (Either CryptoError ByteString)
rsaEncrypt (RSAPublicKey fptr) plaintext = withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString plaintext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_encrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1OAEPPadding)
        "rsaEncrypt: failed"

-- | RSA-OAEP decrypt ciphertext with a private key.
rsaDecrypt :: RSAKeyPair -> ByteString -> IO (Either CryptoError ByteString)
rsaDecrypt (RSAKeyPair fptr) ciphertext = withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString ciphertext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_decrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1OAEPPadding)
        "rsaDecrypt: failed"

-- | RSA PKCS#1 v1.5 encrypt plaintext with a public key.
--
-- __WARNING:__ RSA PKCS#1 v1.5 encryption is vulnerable to
-- Bleichenbacher-style adaptive chosen-ciphertext attacks. The error return
-- on padding failure creates an oracle. Use 'rsaEncrypt' (OAEP) instead for
-- new protocols. This function is provided only for legacy compatibility.
{-# DEPRECATED rsaEncryptPKCS1 "Use rsaEncrypt (OAEP) instead. PKCS#1 v1.5 encryption is vulnerable to Bleichenbacher-style attacks." #-}
rsaEncryptPKCS1 :: RSAPublicKey -> ByteString -> IO (Either CryptoError ByteString)
rsaEncryptPKCS1 (RSAPublicKey fptr) plaintext = withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString plaintext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_encrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1Padding)
        "rsaEncryptPKCS1: failed"

-- | RSA PKCS#1 v1.5 decrypt ciphertext with a private key.
--
-- __WARNING:__ RSA PKCS#1 v1.5 encryption is vulnerable to
-- Bleichenbacher-style adaptive chosen-ciphertext attacks. The error return
-- on padding failure creates an oracle. Use 'rsaDecrypt' (OAEP) instead for
-- new protocols. This function is provided only for legacy compatibility.
{-# DEPRECATED rsaDecryptPKCS1 "Use rsaDecrypt (OAEP) instead. PKCS#1 v1.5 encryption is vulnerable to Bleichenbacher-style attacks." #-}
rsaDecryptPKCS1 :: RSAKeyPair -> ByteString -> IO (Either CryptoError ByteString)
rsaDecryptPKCS1 (RSAKeyPair fptr) ciphertext = withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString ciphertext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_decrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1Padding)
        "rsaDecryptPKCS1: failed"

-- | Get the RSA key size in bits from a public key.
rsaPublicBits :: RSAPublicKey -> IO Int
rsaPublicBits (RSAPublicKey fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_bits rsa

-- | Get the RSA modulus size in bytes from a public key.
rsaPublicSize :: RSAPublicKey -> IO Int
rsaPublicSize (RSAPublicKey fptr) = withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_size rsa
