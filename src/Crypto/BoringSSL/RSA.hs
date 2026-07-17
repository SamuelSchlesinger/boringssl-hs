-- | RSA encryption and digital signatures.
--
-- Supports PKCS#1 v1.5 and PSS signing, and OAEP encryption.
-- Key serialization uses DER-encoded PKCS#1 format.
--
-- __Key size guidance:__
--
-- * 2048 bits is the minimum accepted by this library (and by NIST SP 800-131A
--   through 2030).
-- * 3072 bits provides ~128-bit security and is recommended for new
--   applications.
-- * 4096 bits is appropriate when long-term key durability matters.
--
-- __Signature scheme selection:__
--
-- * Prefer 'rsaSignPSS' \/ 'rsaVerifyPSS' (RSA-PSS) over PKCS#1 v1.5
--   signatures. PSS has a security proof in the random-oracle model.
-- * PKCS#1 v1.5 signatures are provided for interoperability with legacy
--   protocols but are not recommended for new designs.
-- * For encryption, use 'rsaEncrypt' \/ 'rsaDecrypt' (OAEP). PKCS#1 v1.5
--   encryption is __deprecated__ due to Bleichenbacher-style padding-oracle
--   attacks.
module Crypto.BoringSSL.RSA
  ( -- * Key types
    RSAKeyPair
  , RSAPublicKey
    -- * Key generation
  , generateRSAKeyPair
    -- * Serialization
  , publicKeyToBytes
  , publicKeyFromBytes
  , privateKeyToBytes
  , privateKeyToSecureBytes
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
  ) where

import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask, onException)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.SecureBytes
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
-- Keys below 2048 bits are rejected, mirroring 'generateRSAKeyPair'.
publicKeyFromBytes :: ByteString -> IO (Either CryptoError RSAPublicKey)
publicKeyFromBytes bs = withBoundThread $
  withByteString bs $ \ptr len -> runExceptT $ maskE_ $ do
    liftIO clearBoringSSLError
    rsa <- liftIO (c_RSA_public_key_from_bytes ptr len)
      >>= nonNull (OperationFailed "publicKeyFromBytes: RSA_public_key_from_bytes failed")
    fptr <- liftIO $ newForeignPtr c_RSA_free_funptr rsa
    bits <- liftIO $ fromIntegral <$> c_RSA_bits rsa
    if (bits :: Int) < 2048
      then throwE (InvalidInput ("publicKeyFromBytes: key is " ++ show bits ++ " bits; minimum is 2048"))
      else return (RSAPublicKey fptr)

-- | Serialize the private key to DER-encoded PKCS#1 format.
privateKeyToBytes :: RSAKeyPair -> IO (Either CryptoError ByteString)
privateKeyToBytes (RSAKeyPair fptr) = withBoundThread $
  withForeignPtr fptr $ \rsa -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
      liftIO clearBoringSSLError
      rc <- liftIO $ c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsa
      checkRCError "privateKeyToBytes: RSA_private_key_to_bytes failed" rc
      liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr

-- | Serialize the private key to DER-encoded PKCS#1 format, returning
-- 'SecureBytes' that will be zeroized on finalization.
-- Prefer this over 'privateKeyToBytes' to avoid leaving private key
-- material in unprotected memory.
privateKeyToSecureBytes :: RSAKeyPair -> IO (Either CryptoError SecureBytes)
privateKeyToSecureBytes (RSAKeyPair fptr) = withBoundThread $
  withForeignPtr fptr $ \rsa -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
      liftIO clearBoringSSLError
      rc <- liftIO $ c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsa
      checkRCError "privateKeyToSecureBytes: RSA_private_key_to_bytes failed" rc
      liftIO $ packOpenSSLBufferSecure outPtrPtr outLenPtr

-- | Deserialize a private key from DER-encoded PKCS#1 format.
-- Keys below 2048 bits are rejected, mirroring 'generateRSAKeyPair'.
privateKeyFromBytes :: ByteString -> IO (Either CryptoError RSAKeyPair)
privateKeyFromBytes bs = withBoundThread $
  withByteString bs $ \ptr len -> runExceptT $ maskE_ $ do
    liftIO clearBoringSSLError
    rsa <- liftIO (c_RSA_private_key_from_bytes ptr len)
      >>= nonNull (OperationFailed "privateKeyFromBytes: RSA_private_key_from_bytes failed")
    fptr <- liftIO $ newForeignPtr c_RSA_free_funptr rsa
    bits <- liftIO $ fromIntegral <$> c_RSA_bits rsa
    if (bits :: Int) < 2048
      then throwE (InvalidInput ("privateKeyFromBytes: key is " ++ show bits ++ " bits; minimum is 2048"))
      else return (RSAKeyPair fptr)

-- | The RSA key size in bits. Pure: the key is immutable.
rsaBits :: RSAKeyPair -> Int
rsaBits (RSAKeyPair fptr) = unsafePerformIO $ withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_bits rsa
{-# NOINLINE rsaBits #-}

-- | The RSA modulus size in bytes. Pure: the key is immutable.
rsaSize :: RSAKeyPair -> Int
rsaSize (RSAKeyPair fptr) = unsafePerformIO $ withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_size rsa
{-# NOINLINE rsaSize #-}

-- | PKCS#1 v1.5 sign a pre-hashed digest.
-- The @digest@ parameter must be the hash of the message produced by the
-- hash function corresponding to @algo@ (e.g. if @algo@ is 'SHA256',
-- pass the output of 'Crypto.BoringSSL.Digest.hashSHA256').
-- Returns 'Left' if the algorithm has no NID (e.g. BLAKE2b256).
--
-- Pure: PKCS#1 v1.5 signatures are deterministic.
rsaSign :: Algorithm -> RSAKeyPair -> ByteString -> Either CryptoError ByteString
rsaSign algo _ _
  | Nothing <- ID.algorithmNID algo =
      Left (InvalidInput ("rsaSign: algorithm " ++ show algo ++ " has no NID and cannot be used with PKCS#1 v1.5"))
rsaSign algo (RSAKeyPair fptr) digest = unsafePerformIO $ withBoundThread $ do
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
{-# NOINLINE rsaSign #-}

-- | PKCS#1 v1.5 verify a signature on a pre-hashed digest.
-- The @digest@ must be the hash of the original message using the hash
-- function matching @algo@.
--
-- Pure and fail-closed: 'False' covers invalid signatures, an algorithm
-- with no NID, and any internal failure.
rsaVerify :: Algorithm -> RSAPublicKey -> ByteString -> ByteString -> Bool
rsaVerify algo (RSAPublicKey fptr) digest sig =
  case ID.algorithmNID algo of
    Nothing -> False
    Just nid -> unsafePerformIO $ withBoundThread $
      withForeignPtr fptr $ \rsa ->
        withByteString digest $ \digestPtr digestLen ->
          withByteString sig $ \sigPtr sigLen -> do
            clearBoringSSLError
            rc <- c_RSA_verify nid digestPtr digestLen sigPtr sigLen rsa
            clearBoringSSLError
            return (rc == 1)
{-# NOINLINE rsaVerify #-}

-- | RSA-PSS sign a pre-hashed digest. Uses the same hash for MGF1
-- and salt length equal to the digest size.
--
-- The @digest@ parameter must be the hash of the message produced by the
-- hash function corresponding to @algo@.
rsaSignPSS :: Algorithm -> RSAKeyPair -> ByteString -> IO (Either CryptoError ByteString)
rsaSignPSS algo (RSAKeyPair fptr) digest = withBoundThread $
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
-- The @digest@ must be the hash of the original message using the hash
-- function matching @algo@.
--
-- Pure and fail-closed: 'False' covers invalid signatures and any
-- internal failure.
rsaVerifyPSS :: Algorithm -> RSAPublicKey -> ByteString -> ByteString -> Bool
rsaVerifyPSS algo (RSAPublicKey fptr) digest sig = unsafePerformIO $ withBoundThread $
  withForeignPtr fptr $ \rsa ->
    withByteString digest $ \digestPtr digestLen ->
      withByteString sig $ \sigPtr sigLen -> do
        let md = ID.evpMD algo
            saltLen = fromIntegral (ID.digestSize algo)
        clearBoringSSLError
        rc <- c_RSA_verify_pss_mgf1 rsa digestPtr digestLen md md saltLen sigPtr sigLen
        clearBoringSSLError
        return (rc == 1)
{-# NOINLINE rsaVerifyPSS #-}

-- | RSA-OAEP encrypt plaintext with a public key. In 'IO' because OAEP
-- padding is randomized.
--
-- BoringSSL fixes the OAEP and MGF-1 digest to SHA-1 (the universally
-- interoperable choice; not a security concern for OAEP's use of the
-- hash). Peers must decrypt with OAEP-SHA-1 parameters.
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

-- | RSA-OAEP decrypt ciphertext with a private key. Pure: decryption is
-- deterministic. Uses OAEP-SHA-1 parameters (see 'rsaEncrypt').
rsaDecrypt :: RSAKeyPair -> ByteString -> Either CryptoError ByteString
rsaDecrypt (RSAKeyPair fptr) ciphertext = unsafePerformIO $ withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString ciphertext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_decrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1OAEPPadding)
        "rsaDecrypt: failed"
{-# NOINLINE rsaDecrypt #-}

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
rsaDecryptPKCS1 :: RSAKeyPair -> ByteString -> Either CryptoError ByteString
rsaDecryptPKCS1 (RSAKeyPair fptr) ciphertext = unsafePerformIO $ withBoundThread $
  withForeignPtr fptr $ \rsa -> do
    modSize <- fromIntegral <$> c_RSA_size rsa
    withByteString ciphertext $ \inPtr inLen -> runExceptT $
      withOutputBuffer modSize
        (\outPtr outLenPtr ->
          c_RSA_decrypt rsa outLenPtr (castPtr outPtr) (fromIntegral modSize)
            inPtr inLen rsaPKCS1Padding)
        "rsaDecryptPKCS1: failed"
{-# NOINLINE rsaDecryptPKCS1 #-}

-- | The RSA key size in bits from a public key. Pure: the key is immutable.
rsaPublicBits :: RSAPublicKey -> Int
rsaPublicBits (RSAPublicKey fptr) = unsafePerformIO $ withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_bits rsa
{-# NOINLINE rsaPublicBits #-}

-- | The RSA modulus size in bytes from a public key. Pure: the key is immutable.
rsaPublicSize :: RSAPublicKey -> Int
rsaPublicSize (RSAPublicKey fptr) = unsafePerformIO $ withForeignPtr fptr $ \rsa ->
  fromIntegral <$> c_RSA_size rsa
{-# NOINLINE rsaPublicSize #-}
