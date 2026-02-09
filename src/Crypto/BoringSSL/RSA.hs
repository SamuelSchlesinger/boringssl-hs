module Crypto.BoringSSL.RSA
  ( RSAKeyPair(..)
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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable

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

-- | RSA_PKCS1_OAEP_PADDING = 4
rsaPKCS1OAEPPadding :: CInt
rsaPKCS1OAEPPadding = 4

-- | Generate a new RSA key pair.
generateRSAKeyPair :: Int -> IO RSAKeyPair
generateRSAKeyPair bits = do
  rsa <- c_RSA_new
  if rsa == nullPtr
    then fail "generateRSAKeyPair: RSA_new failed"
    else do
      e <- c_BN_new
      if e == nullPtr
        then do
          c_RSA_free rsa
          fail "generateRSAKeyPair: BN_new failed"
        else do
          _ <- c_BN_set_word e 65537
          rc <- c_RSA_generate_key_ex rsa (fromIntegral bits) e nullPtr
          c_BN_free e
          if rc /= 1
            then do
              c_RSA_free rsa
              fail "generateRSAKeyPair: RSA_generate_key_ex failed"
            else do
              fptr <- newForeignPtr c_RSA_free_funptr rsa
              return (RSAKeyPair fptr)

-- | Serialize the public key to DER-encoded PKCS#1 format.
publicKeyToBytes :: RSAKeyPair -> IO ByteString
publicKeyToBytes (RSAKeyPair fptr) =
  withForeignPtr fptr $ \rsa ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_RSA_public_key_to_bytes outPtrPtr outLenPtr rsa
        if rc /= 1
          then fail "publicKeyToBytes: RSA_public_key_to_bytes failed"
          else packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a public key from DER-encoded PKCS#1 format.
publicKeyFromBytes :: ByteString -> IO RSAPublicKey
publicKeyFromBytes bs =
  withByteString bs $ \ptr len -> do
    rsa <- c_RSA_public_key_from_bytes ptr len
    if rsa == nullPtr
      then fail "publicKeyFromBytes: RSA_public_key_from_bytes failed"
      else do
        fptr <- newForeignPtr c_RSA_free_funptr rsa
        return (RSAPublicKey fptr)

-- | Serialize the private key to DER-encoded PKCS#1 format.
privateKeyToBytes :: RSAKeyPair -> IO ByteString
privateKeyToBytes (RSAKeyPair fptr) =
  withForeignPtr fptr $ \rsa ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsa
        if rc /= 1
          then fail "privateKeyToBytes: RSA_private_key_to_bytes failed"
          else packOpenSSLBuffer outPtrPtr outLenPtr

-- | Deserialize a private key from DER-encoded PKCS#1 format.
privateKeyFromBytes :: ByteString -> IO RSAKeyPair
privateKeyFromBytes bs =
  withByteString bs $ \ptr len -> do
    rsa <- c_RSA_private_key_from_bytes ptr len
    if rsa == nullPtr
      then fail "privateKeyFromBytes: RSA_private_key_from_bytes failed"
      else do
        fptr <- newForeignPtr c_RSA_free_funptr rsa
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
