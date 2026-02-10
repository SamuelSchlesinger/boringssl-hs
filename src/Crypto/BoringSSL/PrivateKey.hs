-- | Auto-detect private key loading from DER or PEM.
--
-- Supports RSA, EC (P-256, P-384, P-521), Ed25519, and X25519 keys.
-- DER handles PKCS#1, PKCS#8, and SEC1 formats automatically.
module Crypto.BoringSSL.PrivateKey
  ( SomePrivateKey(..)
  , loadPrivateKeyDER
  , loadPrivateKeyPEM
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (bracket, mask_)

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

-- | A private key of any supported type.
data SomePrivateKey
  = SomeRSAKey RSA.RSAKeyPair
  | SomeECKey ECCurve ECKeyPair
  | SomeEd25519Key Ed25519.PrivateKey
  | SomeX25519Key ByteString

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
loadPrivateKeyDER :: ByteString -> IO (Either CryptoError SomePrivateKey)
loadPrivateKeyDER bs =
  withByteString bs $ \dataPtr dataLen ->
    alloca $ \inpPtr -> do
      poke inpPtr dataPtr
      mask_ $ do
        pkey <- c_d2i_AutoPrivateKey nullPtr inpPtr (fromIntegral dataLen)
        if pkey == nullPtr
          then return (Left (DecodeError "loadPrivateKeyDER: d2i_AutoPrivateKey failed"))
          else bracket (return pkey) c_EVP_PKEY_free $ \pk ->
            evpPKeyToSomeKey pk

-- | Load a private key from PEM encoding.
loadPrivateKeyPEM :: ByteString -> IO (Either CryptoError SomePrivateKey)
loadPrivateKeyPEM bs =
  withByteString bs $ \dataPtr dataLen -> mask_ $ do
    bio <- c_BIO_new_mem_buf dataPtr (fromIntegral dataLen)
    if bio == nullPtr
      then return (Left (AllocationFailure "loadPrivateKeyPEM: BIO_new_mem_buf failed"))
      else do
        pkey <- c_PEM_read_bio_PrivateKey bio nullPtr nullPtr nullPtr
        _ <- c_BIO_free bio
        if pkey == nullPtr
          then return (Left (DecodeError "loadPrivateKeyPEM: PEM_read_bio_PrivateKey failed"))
          else bracket (return pkey) c_EVP_PKEY_free $ \pk ->
            evpPKeyToSomeKey pk

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
extractRSA pkey = do
  rsaPtr <- c_EVP_PKEY_get0_RSA pkey
  if rsaPtr == nullPtr
    then return (Left (OperationFailed "loadPrivateKey: EVP_PKEY_get0_RSA returned NULL"))
    else alloca $ \outPtrPtr -> alloca $ \outLenPtr -> do
      rc <- c_RSA_private_key_to_bytes outPtrPtr outLenPtr rsaPtr
      if rc /= 1
        then return (Left (OperationFailed "loadPrivateKey: RSA_private_key_to_bytes failed"))
        else do
          derBytes <- packOpenSSLBuffer outPtrPtr outLenPtr
          result <- RSA.privateKeyFromBytes derBytes
          return (fmap SomeRSAKey result)

extractEC :: Ptr EVP_PKEY -> IO (Either CryptoError SomePrivateKey)
extractEC pkey = do
  ecKey <- c_EVP_PKEY_get0_EC_KEY pkey
  if ecKey == nullPtr
    then return (Left (OperationFailed "loadPrivateKey: EVP_PKEY_get0_EC_KEY returned NULL"))
    else do
      groupPtr <- c_EC_KEY_get0_group ecKey
      if groupPtr == nullPtr
        then return (Left (OperationFailed "loadPrivateKey: EC_KEY_get0_group returned NULL"))
        else do
          nid <- c_EC_GROUP_get_curve_name groupPtr
          case nidToCurve nid of
            Nothing -> return (Left (DecodeError ("loadPrivateKey: unsupported EC curve NID " ++ show nid)))
            Just curve -> do
              degree <- c_EC_GROUP_get_degree groupPtr
              let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
              privBn <- c_EC_KEY_get0_private_key ecKey
              if privBn == nullPtr
                then return (Left (OperationFailed "loadPrivateKey: no private key"))
                else do
                  fptr <- BSI.mallocByteString numBytes
                  rc <- withForeignPtr fptr $ \ptr ->
                    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) privBn
                  if rc /= 1
                    then return (Left (OperationFailed "loadPrivateKey: BN_bn2bin_padded failed"))
                    else do
                      let privBytes = BSI.BS fptr numBytes
                      result <- ecKeyPairFromPrivateBytes curve privBytes
                      return (fmap (SomeECKey curve) result)

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
getRawPrivateKey pkey expectedLen =
  alloca $ \outLenPtr -> do
    poke outLenPtr 0
    rc <- c_EVP_PKEY_get_raw_private_key pkey nullPtr outLenPtr
    if rc /= 1
      then return (Left (OperationFailed "getRawPrivateKey: size query failed"))
      else do
        len <- peek outLenPtr
        let actualLen = fromIntegral len :: Int
        if actualLen /= expectedLen
          then return (Left (OperationFailed ("getRawPrivateKey: unexpected size " ++ show actualLen)))
          else do
            fout <- BSI.mallocByteString actualLen
            rc2 <- withForeignPtr fout $ \outPtr ->
              c_EVP_PKEY_get_raw_private_key pkey (castPtr outPtr) outLenPtr
            if rc2 /= 1
              then return (Left (OperationFailed "getRawPrivateKey: failed"))
              else return (Right (BSI.BS fout actualLen))

nidToCurve :: CInt -> Maybe ECCurve
nidToCurve n
  | n == curveNID P256 = Just P256
  | n == curveNID P384 = Just P384
  | n == curveNID P521 = Just P521
  | otherwise          = Nothing
