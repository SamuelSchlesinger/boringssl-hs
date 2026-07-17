-- | Auto-detect private key loading from DER or PEM.
--
-- Supports RSA, EC (P-256, P-384, P-521), Ed25519, and X25519 keys.
-- DER handles PKCS#1, PKCS#8, and SEC1 formats automatically.
module Crypto.BoringSSL.PrivateKey
  ( SomePrivateKey(..)
  , loadPrivateKeyDER
  , loadPrivateKeyPEM
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable
import Control.Exception (bracket, mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.X509
import Crypto.BoringSSL.Internal.FFI.RSA (c_RSA_private_key_to_bytes)
import Crypto.BoringSSL.Internal.FFI.ECKey
  ( c_EC_KEY_get0_group, c_EC_KEY_get0_private_key
  , c_EC_GROUP_get_degree, c_BN_bn2bin_padded )
import Crypto.BoringSSL.Internal.ECKey
  ( ECCurve(..), ECKeyPair, ecKeyPairFromPrivateBytes, curveNID )
import qualified Crypto.BoringSSL.RSA as RSA
import qualified Crypto.BoringSSL.Ed25519 as Ed25519

-- | A private key of any supported type, as detected by 'loadPrivateKeyDER'
-- or 'loadPrivateKeyPEM'.
data SomePrivateKey
  = SomeRSAKey RSA.RSAKeyPair
    -- ^ An RSA private key.
  | SomeECKey ECCurve ECKeyPair
    -- ^ An EC private key on the given curve (P-256, P-384, or P-521).
  | SomeEd25519Key Ed25519.PrivateKey
    -- ^ An Ed25519 signing key.
  | SomeX25519Key ByteString
    -- ^ An X25519 private key (32 raw bytes).

instance Show SomePrivateKey where
  show (SomeRSAKey _)       = "SomeRSAKey <key>"
  show (SomeECKey c _)      = "SomeECKey " ++ show c ++ " <key>"
  show (SomeEd25519Key _)   = "SomeEd25519Key <key>"
  show (SomeX25519Key _)    = "SomeX25519Key <key>"

-- | NID constants for EVP_PKEY types.
evpPKeyRSA, evpPKeyEC, evpPKeyED25519, evpPKeyX25519 :: CInt
evpPKeyRSA     = 6
evpPKeyEC      = 408
evpPKeyED25519 = 949
evpPKeyX25519  = 948

-- | Load a private key from DER encoding.
-- Automatically detects PKCS#1 (RSA), PKCS#8, and SEC1 (EC) formats.
-- Pure: parsing is deterministic.
loadPrivateKeyDER :: ByteString -> Either CryptoError SomePrivateKey
loadPrivateKeyDER bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    alloca $ \inpPtr -> do
      poke inpPtr dataPtr
      mask_ $ do
        pkey <- c_d2i_AutoPrivateKey nullPtr inpPtr (fromIntegral dataLen)
        if pkey == nullPtr
          then return (Left (DecodeError "loadPrivateKeyDER: d2i_AutoPrivateKey failed"))
          else bracket (return pkey) c_EVP_PKEY_free $ \pk ->
            evpPKeyToSomeKey pk
{-# NOINLINE loadPrivateKeyDER #-}

-- | Load a private key from PEM encoding. Pure: parsing is
-- deterministic.
loadPrivateKeyPEM :: ByteString -> Either CryptoError SomePrivateKey
loadPrivateKeyPEM bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen -> runExceptT $ maskE_ $ do
    bio <- liftIO (c_BIO_new_mem_buf dataPtr (fromIntegral dataLen))
      >>= nonNull (AllocationFailure "loadPrivateKeyPEM: BIO_new_mem_buf failed")
    pkey <- liftIO $ c_PEM_read_bio_PrivateKey bio nullPtr nullPtr nullPtr
    _ <- liftIO $ c_BIO_free bio
    _ <- nonNull (DecodeError "loadPrivateKeyPEM: PEM_read_bio_PrivateKey failed") pkey
    ExceptT $ bracket (return pkey) c_EVP_PKEY_free $ \pk ->
      evpPKeyToSomeKey pk
{-# NOINLINE loadPrivateKeyPEM #-}

-- | Convert an EVP_PKEY to a SomePrivateKey by detecting type and
-- serializing the key material into Haskell-managed types.
evpPKeyToSomeKey :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
evpPKeyToSomeKey pkey = do
  keyType <- c_EVP_PKEY_id pkey
  if keyType == evpPKeyRSA then extractRSA pkey
  else if keyType == evpPKeyEC then extractEC pkey
  else if keyType == evpPKeyED25519 then extractEd25519 pkey
  else if keyType == evpPKeyX25519 then extractX25519 pkey
  else return (Left (DecodeError ("loadPrivateKey: unsupported key type " ++ show keyType)))

extractRSA :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
extractRSA pkey = runExceptT $ do
  rsaPtr <- liftIO (c_EVP_PKEY_get0_RSA pkey)
    >>= nonNull (OperationFailed "loadPrivateKey: EVP_PKEY_get0_RSA returned NULL")
  allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
    rc <- liftIO $ c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsaPtr
    checkRC (OperationFailed "loadPrivateKey: RSA_private_key_to_bytes failed") rc
    derBytes <- liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr
    result <- ExceptT $ RSA.privateKeyFromBytes derBytes
    return (SomeRSAKey result)

extractEC :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
extractEC pkey = runExceptT $ do
  ecKey <- liftIO (c_EVP_PKEY_get0_EC_KEY pkey)
    >>= nonNull (OperationFailed "loadPrivateKey: EVP_PKEY_get0_EC_KEY returned NULL")
  groupPtr <- liftIO (c_EC_KEY_get0_group ecKey)
    >>= nonNull (OperationFailed "loadPrivateKey: EC_KEY_get0_group returned NULL")
  nid <- liftIO $ c_EC_GROUP_get_curve_name groupPtr
  curve <- case nidToCurve nid of
    Nothing -> throwE (DecodeError ("loadPrivateKey: unsupported EC curve NID " ++ show nid))
    Just c  -> return c
  degree <- liftIO $ c_EC_GROUP_get_degree groupPtr
  let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
  privBn <- liftIO (c_EC_KEY_get0_private_key ecKey)
    >>= nonNull (OperationFailed "loadPrivateKey: no private key")
  bsFptr <- liftIO $ BSI.mallocByteString numBytes
  rc <- liftIO $ withForeignPtr bsFptr $ \ptr ->
    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) privBn
  checkRC (OperationFailed "loadPrivateKey: BN_bn2bin_padded failed") rc
  let privBytes = BSI.BS bsFptr numBytes
  result <- ExceptT $ ecKeyPairFromPrivateBytes curve privBytes
  return (SomeECKey curve result)

extractEd25519 :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
extractEd25519 pkey = runExceptT $ do
  seed <- ExceptT $ getRawPrivateKey pkey 32
  case Ed25519.keyPairFromSeed seed of
    Left err -> throwE err
    Right (_, privKey) -> return (SomeEd25519Key privKey)

extractX25519 :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
extractX25519 pkey = runExceptT $ do
  raw <- ExceptT $ getRawPrivateKey pkey 32
  return (SomeX25519Key raw)

getRawPrivateKey :: Ptr EVP_PKEY -> Int -> IO (Either CryptoError ByteString)
getRawPrivateKey pkey expectedLen = runExceptT $
  allocaE $ \outLenPtr -> do
    liftIO $ poke outLenPtr 0
    rc <- liftIO $ c_EVP_PKEY_get_raw_private_key pkey nullPtr outLenPtr
    checkRC (OperationFailed "getRawPrivateKey: size query failed") rc
    len <- liftIO $ peek outLenPtr
    let actualLen = fromIntegral len :: Int
    if actualLen /= expectedLen
      then throwE (OperationFailed ("getRawPrivateKey: unexpected size " ++ show actualLen))
      else do
        fout <- liftIO $ BSI.mallocByteString actualLen
        rc2 <- liftIO $ withForeignPtr fout $ \outPtr ->
          c_EVP_PKEY_get_raw_private_key pkey (castPtr outPtr) outLenPtr
        checkRC (OperationFailed "getRawPrivateKey: failed") rc2
        return (BSI.BS fout actualLen)

nidToCurve :: CInt -> Maybe ECCurve
nidToCurve n
  | n == curveNID P256 = Just P256
  | n == curveNID P384 = Just P384
  | n == curveNID P521 = Just P521
  | otherwise          = Nothing
