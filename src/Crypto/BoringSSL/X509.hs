-- | X.509 certificate parsing, inspection, and verification.
--
-- Provides DER and PEM parsing, DER serialization, name accessors,
-- version, serial number, validity times, self-signed verification,
-- public key extraction, extension accessors, chain verification,
-- signature algorithm info, and DN DER serialization.
module Crypto.BoringSSL.X509
  ( X509Cert
  , parseDER
  , parsePEM
  , toDER
  , subjectName
  , issuerName
  , version
  , serialNumberHex
  , notBefore
  , notAfter
  , verifySelfSigned
    -- * Public key extraction (Feature 6)
  , CertPubKey(..)
  , certPublicKey
    -- * Certificate extensions (Feature 7)
  , KeyUsageFlag(..)
  , certKeyUsage
  , certBasicConstraints
  , GeneralName(..)
  , certSubjectAltNames
    -- * Chain verification (Feature 8)
  , X509Store
  , newX509Store
  , addTrustAnchor
  , VerifyResult(..)
  , verifyCertChain
    -- * Signature algorithm (Feature 9)
  , SignatureAlgInfo(..)
  , certSignatureAlgorithm
    -- * DN as DER (Feature 10)
  , certSubjectDER
  , certIssuerDER
    -- * Error type
  , CryptoError(..)
  ) where

import Control.Exception (bracket, mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Data.Char (digitToInt, isHexDigit)
import Data.Int (Int64)
import Foreign.C.String
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Array
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_free)
import Crypto.BoringSSL.Internal.FFI.X509
import Crypto.BoringSSL.Internal.FFI.ECKey
  ( c_EC_KEY_get0_group, c_EC_KEY_get0_public_key
  , c_EC_POINT_point2oct
  )
import Crypto.BoringSSL.Internal.FFI.RSA
  ( c_RSA_public_key_to_bytes )
import Crypto.BoringSSL.Internal.ECKey
  ( ECCurve(..), ECPublicKey, ecPublicKeyFromBytes, curveNID )
import qualified Crypto.BoringSSL.RSA as RSA
import qualified Crypto.BoringSSL.PEM as PEM

-- | An X.509 certificate. Automatically freed when garbage collected.
newtype X509Cert = X509Cert (ForeignPtr X509)

------------------------------------------------------------------------
-- Parsing and serialization
------------------------------------------------------------------------

-- | Parse a DER-encoded X.509 certificate.
parseDER :: ByteString -> Either CryptoError X509Cert
parseDER bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    alloca $ \inpPtr -> do
      poke inpPtr dataPtr
      alloca $ \outPtr -> do
        poke outPtr nullPtr
        mask_ $ do
          cert <- c_d2i_X509 outPtr inpPtr (fromIntegral dataLen)
          if cert == nullPtr
            then return (Left (DecodeError "X509.parseDER: failed to parse DER"))
            else do
              fptr <- newForeignPtr c_X509_free_funptr cert
              return (Right (X509Cert fptr))
{-# NOINLINE parseDER #-}

-- | Parse a PEM-encoded X.509 certificate.
parsePEM :: ByteString -> Either CryptoError X509Cert
parsePEM pem =
  case PEM.pemDecode pem of
    Right ("CERTIFICATE", der) -> parseDER der
    Right (label, _) -> Left (DecodeError ("X509.parsePEM: expected CERTIFICATE, got " ++ label))
    Left err -> Left err

-- | Serialize an X.509 certificate to DER encoding.
toDER :: X509Cert -> Either CryptoError ByteString
toDER (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    len <- c_i2d_X509 certPtr nullPtr
    if len <= 0
      then return (Left (OperationFailed "X509.toDER: i2d_X509 failed to compute length"))
      else do
        outFPtr <- BSI.mallocByteString (fromIntegral len)
        withForeignPtr outFPtr $ \outBuf -> do
          alloca $ \outPtrPtr -> do
            poke outPtrPtr (castPtr outBuf)
            actualLen <- c_i2d_X509 certPtr outPtrPtr
            if actualLen <= 0
              then return (Left (OperationFailed "X509.toDER: i2d_X509 failed to serialize"))
              else return (Right (BSI.BS outFPtr (fromIntegral actualLen)))
{-# NOINLINE toDER #-}

------------------------------------------------------------------------
-- Accessors
------------------------------------------------------------------------

subjectName :: X509Cert -> String
subjectName (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_subject_name certPtr
    if namePtr == nullPtr
      then return ""
      else allocaArray 1024 $ \buf -> do
        result <- c_X509_NAME_oneline namePtr buf 1024
        if result == nullPtr
          then return ""
          else peekCString buf
{-# NOINLINE subjectName #-}

issuerName :: X509Cert -> String
issuerName (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_issuer_name certPtr
    if namePtr == nullPtr
      then return ""
      else allocaArray 1024 $ \buf -> do
        result <- c_X509_NAME_oneline namePtr buf 1024
        if result == nullPtr
          then return ""
          else peekCString buf
{-# NOINLINE issuerName #-}

version :: X509Cert -> Int
version (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    v <- c_X509_get_version certPtr
    return (fromIntegral v + 1)
{-# NOINLINE version #-}

serialNumberHex :: X509Cert -> String
serialNumberHex (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    serialPtr <- c_X509_get0_serialNumber certPtr
    if serialPtr == nullPtr
      then return ""
      else do
        bnPtr <- c_ASN1_INTEGER_to_BN serialPtr nullPtr
        if bnPtr == nullPtr
          then return ""
          else do
            hexPtr <- c_BN_bn2hex bnPtr
            c_BN_free bnPtr
            if hexPtr == nullPtr
              then return ""
              else do
                hexStr <- peekCString hexPtr
                c_OPENSSL_free hexPtr
                return hexStr
{-# NOINLINE serialNumberHex #-}

notBefore :: X509Cert -> Either CryptoError Int64
notBefore (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    timePtr <- c_X509_get0_notBefore certPtr
    if timePtr == nullPtr
      then return (Left (OperationFailed "X509.notBefore: no notBefore time"))
      else alloca $ \outPtr -> do
        rc <- c_ASN1_TIME_to_posix timePtr outPtr
        if rc == 1
          then do
            t <- peek outPtr
            return (Right t)
          else return (Left (OperationFailed "X509.notBefore: time conversion failed"))
{-# NOINLINE notBefore #-}

notAfter :: X509Cert -> Either CryptoError Int64
notAfter (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    timePtr <- c_X509_get0_notAfter certPtr
    if timePtr == nullPtr
      then return (Left (OperationFailed "X509.notAfter: no notAfter time"))
      else alloca $ \outPtr -> do
        rc <- c_ASN1_TIME_to_posix timePtr outPtr
        if rc == 1
          then do
            t <- peek outPtr
            return (Right t)
          else return (Left (OperationFailed "X509.notAfter: time conversion failed"))
{-# NOINLINE notAfter #-}

verifySelfSigned :: X509Cert -> Bool
verifySelfSigned (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr ->
    bracket
      (c_X509_get_pubkey certPtr)
      (\pkey -> if pkey /= nullPtr then c_EVP_PKEY_free pkey else return ())
      $ \pkey ->
        if pkey == nullPtr
          then return False
          else do
            rc <- c_X509_verify certPtr pkey
            return (rc == 1)
{-# NOINLINE verifySelfSigned #-}

------------------------------------------------------------------------
-- Feature 6: Public key extraction
------------------------------------------------------------------------

-- | NID constants for EVP_PKEY types.
evpPKeyRSA, evpPKeyEC, evpPKeyED25519 :: CInt
evpPKeyRSA     = 6
evpPKeyEC      = 408
evpPKeyED25519 = 949

-- | The public key extracted from a certificate.
data CertPubKey
  = CertPubKeyRSA RSA.RSAPublicKey
  | CertPubKeyEC ECCurve ECPublicKey
  | CertPubKeyEd25519 ByteString
  | CertPubKeyUnknown Int

instance Show CertPubKey where
  show (CertPubKeyRSA _)     = "CertPubKeyRSA <key>"
  show (CertPubKeyEC c _)    = "CertPubKeyEC " ++ show c ++ " <key>"
  show (CertPubKeyEd25519 b) = "CertPubKeyEd25519 " ++ show (BS.length b) ++ " bytes"
  show (CertPubKeyUnknown n) = "CertPubKeyUnknown " ++ show n

-- | Extract the public key from a certificate.
certPublicKey :: X509Cert -> IO (Either CryptoError CertPubKey)
certPublicKey (X509Cert fptr) =
  withForeignPtr fptr $ \certPtr ->
    bracket (c_X509_get_pubkey certPtr)
            (\pkey -> if pkey /= nullPtr then c_EVP_PKEY_free pkey else return ())
    $ \pkey ->
      if pkey == nullPtr
        then return (Left (OperationFailed "certPublicKey: X509_get_pubkey returned NULL"))
        else do
          keyType <- c_EVP_PKEY_id pkey
          if keyType == evpPKeyRSA then extractRSA pkey
          else if keyType == evpPKeyEC then extractEC pkey
          else if keyType == evpPKeyED25519 then extractEd25519 pkey
          else return (Right (CertPubKeyUnknown (fromIntegral keyType)))
  where
    extractRSA pkey = do
      rsaPtr <- c_EVP_PKEY_get0_RSA pkey
      if rsaPtr == nullPtr
        then return (Left (OperationFailed "certPublicKey: EVP_PKEY_get0_RSA returned NULL"))
        else alloca $ \outPtrPtr -> alloca $ \outLenPtr -> do
          rc <- c_RSA_public_key_to_bytes outPtrPtr outLenPtr rsaPtr
          if rc /= 1
            then return (Left (OperationFailed "certPublicKey: RSA_public_key_to_bytes failed"))
            else do
              derBytes <- packOpenSSLBuffer outPtrPtr outLenPtr
              result <- RSA.publicKeyFromBytes derBytes
              return (fmap CertPubKeyRSA result)

    extractEC pkey = do
      ecKey <- c_EVP_PKEY_get0_EC_KEY pkey
      if ecKey == nullPtr
        then return (Left (OperationFailed "certPublicKey: EVP_PKEY_get0_EC_KEY returned NULL"))
        else do
          groupPtr <- c_EC_KEY_get0_group ecKey
          if groupPtr == nullPtr
            then return (Left (OperationFailed "certPublicKey: EC_KEY_get0_group returned NULL"))
            else do
              nid <- c_EC_GROUP_get_curve_name groupPtr
              case nidToCurve nid of
                Nothing -> return (Right (CertPubKeyUnknown (fromIntegral nid)))
                Just curve -> do
                  pointPtr <- c_EC_KEY_get0_public_key ecKey
                  if pointPtr == nullPtr
                    then return (Left (OperationFailed "certPublicKey: no public point"))
                    else do
                      len <- c_EC_POINT_point2oct groupPtr pointPtr 4 nullPtr 0 nullPtr
                      if len == 0
                        then return (Left (OperationFailed "certPublicKey: point2oct size query failed"))
                        else do
                          pubBytes <- createByteString (fromIntegral len) $ \outPtr ->
                            c_EC_POINT_point2oct groupPtr pointPtr 4 outPtr len nullPtr >> return ()
                          result <- ecPublicKeyFromBytes curve pubBytes
                          return (fmap (CertPubKeyEC curve) result)

    extractEd25519 pkey = runExceptT $ do
      bs <- ExceptT $ alloca $ \outLenPtr -> do
        poke outLenPtr 0
        rc <- c_EVP_PKEY_get_raw_public_key pkey nullPtr outLenPtr
        if rc /= 1
          then return (Left (OperationFailed "certPublicKey: get_raw_public_key size query failed"))
          else do
            len <- peek outLenPtr
            fout <- BSI.mallocByteString (fromIntegral len)
            rc2 <- withForeignPtr fout $ \outPtr ->
              c_EVP_PKEY_get_raw_public_key pkey (castPtr outPtr) outLenPtr
            if rc2 /= 1
              then return (Left (OperationFailed "certPublicKey: get_raw_public_key failed"))
              else do
                actualLen <- peek outLenPtr
                return (Right (BSI.BS fout (fromIntegral actualLen)))
      return (CertPubKeyEd25519 bs)

    nidToCurve :: CInt -> Maybe ECCurve
    nidToCurve n
      | n == curveNID P256 = Just P256
      | n == curveNID P384 = Just P384
      | n == curveNID P521 = Just P521
      | otherwise          = Nothing

------------------------------------------------------------------------
-- Feature 7: Certificate extension accessors
------------------------------------------------------------------------

data KeyUsageFlag
  = DigitalSignature
  | ContentCommitment
  | KeyEncipherment
  | DataEncipherment
  | KeyAgreement
  | KeyCertSign
  | CRLSign
  | EncipherOnly
  | DecipherOnly
  deriving (Eq, Show)

-- | Get the key usage flags from a certificate.
-- Returns @Nothing@ if the key usage extension is not present.
certKeyUsage :: X509Cert -> Maybe [KeyUsageFlag]
certKeyUsage (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    bits <- c_X509_get_key_usage certPtr
    if bits == maxBound  -- UINT32_MAX means not present
      then return Nothing
      else return (Just (decodeKeyUsage (fromIntegral bits)))
  where
    decodeKeyUsage :: Int -> [KeyUsageFlag]
    decodeKeyUsage w =
      [ flag | (bit, flag) <- zip ([0..] :: [Int]) allFlags, w `testBit'` bit ]
    allFlags =
      [ DigitalSignature, ContentCommitment, KeyEncipherment
      , DataEncipherment, KeyAgreement, KeyCertSign, CRLSign
      , EncipherOnly, DecipherOnly ]
    testBit' :: Int -> Int -> Bool
    testBit' n b = (n `div` (2^b)) `mod` 2 == 1
{-# NOINLINE certKeyUsage #-}

-- | Get the basic constraints extension.
-- Returns @Nothing@ if not present, @Just (isCA, maybePathLen)@ otherwise.
certBasicConstraints :: X509Cert -> Maybe (Bool, Maybe Int)
certBasicConstraints (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    -- NID_basic_constraints = 87
    bcPtr <- c_X509_get_ext_d2i certPtr 87 nullPtr nullPtr
    if bcPtr == nullPtr
      then return Nothing
      else do
        let bc = castPtr bcPtr
        ca <- c_bssl_basic_constraints_ca bc
        pathlenPtr <- c_bssl_basic_constraints_pathlen bc
        pathlen <- if pathlenPtr == nullPtr
          then return Nothing
          else do
            bnPtr <- c_ASN1_INTEGER_to_BN pathlenPtr nullPtr
            if bnPtr == nullPtr
              then return Nothing
              else do
                hexPtr <- c_BN_bn2hex bnPtr
                c_BN_free bnPtr
                if hexPtr == nullPtr
                  then return Nothing
                  else do
                    hexStr <- peekCString hexPtr
                    c_OPENSSL_free hexPtr
                    return (safeReadHex hexStr)
        c_BASIC_CONSTRAINTS_free bc
        return (Just (ca /= 0, pathlen))
{-# NOINLINE certBasicConstraints #-}

-- | A Subject Alternative Name entry.
data GeneralName
  = GNEmail String
  | GNDNS String
  | GNURI String
  | GNIP ByteString
  | GNOther Int ByteString
  deriving (Eq, Show)

-- | Get the subject alternative names from a certificate.
-- Returns an empty list if the extension is not present.
certSubjectAltNames :: X509Cert -> [GeneralName]
certSubjectAltNames (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    -- NID_subject_alt_name = 85
    gensPtr <- c_X509_get_ext_d2i certPtr 85 nullPtr nullPtr
    if gensPtr == nullPtr
      then return []
      else do
        let gens = castPtr gensPtr
        n <- c_bssl_sk_GENERAL_NAME_num gens
        names <- mapM (extractGen gens) [0 .. n - 1]
        c_GENERAL_NAMES_free gens
        return names
  where
    extractGen gens i = do
      gen <- c_bssl_sk_GENERAL_NAME_value gens i
      genType <- c_bssl_general_name_type gen
      let typeInt = fromIntegral genType
      case genType of
        1 -> do  -- GEN_EMAIL
          dataPtr <- c_bssl_general_name_data gen
          str <- asn1StringToBS dataPtr
          return (GNEmail (bsToString str))
        2 -> do  -- GEN_DNS
          dataPtr <- c_bssl_general_name_data gen
          str <- asn1StringToBS dataPtr
          return (GNDNS (bsToString str))
        6 -> do  -- GEN_URI
          dataPtr <- c_bssl_general_name_data gen
          str <- asn1StringToBS dataPtr
          return (GNURI (bsToString str))
        7 -> do  -- GEN_IPADD
          dataPtr <- c_bssl_general_name_data gen
          str <- asn1StringToBS dataPtr
          return (GNIP str)
        _ -> return (GNOther typeInt BS.empty)

    asn1StringToBS :: Ptr ASN1_STRING -> IO ByteString
    asn1StringToBS ptr = do
      dataP <- c_bssl_ASN1_STRING_get0_data ptr
      len <- c_bssl_ASN1_STRING_length ptr
      BS.packCStringLen (castPtr dataP, fromIntegral len)

    bsToString :: ByteString -> String
    bsToString = map (toEnum . fromEnum) . BS.unpack
{-# NOINLINE certSubjectAltNames #-}

-- | Safely parse a hex string to an Int, returning Nothing on invalid input.
safeReadHex :: String -> Maybe Int
safeReadHex s
  | null s         = Nothing
  | all isHexDigit s = Just (foldl (\acc c -> acc * 16 + digitToInt c) 0 s)
  | otherwise      = Nothing

------------------------------------------------------------------------
-- Feature 8: X.509 chain verification
------------------------------------------------------------------------

-- | A trust store containing trust anchor certificates.
newtype X509Store = X509Store (ForeignPtr X509_STORE)

-- | The result of X.509 chain verification.
data VerifyResult
  = VerifyOK
  | VerifyFailed Int String
  deriving (Eq, Show)

-- | Create a new empty trust store.
newX509Store :: IO X509Store
newX509Store = mask_ $ do
  storePtr <- c_X509_STORE_new
  if storePtr == nullPtr
    then fail "newX509Store: X509_STORE_new returned NULL"
    else do
      fptr <- newForeignPtr c_X509_STORE_free_funptr storePtr
      return (X509Store fptr)

-- | Add a trust anchor certificate to the store.
addTrustAnchor :: X509Store -> X509Cert -> IO ()
addTrustAnchor (X509Store storeFptr) (X509Cert certFptr) =
  withForeignPtr storeFptr $ \storePtr ->
    withForeignPtr certFptr $ \certPtr -> do
      rc <- c_X509_STORE_add_cert storePtr certPtr
      if rc /= 1
        then fail "addTrustAnchor: X509_STORE_add_cert failed"
        else return ()

-- | Verify a certificate chain against a trust store.
verifyCertChain :: X509Store -> X509Cert -> [X509Cert] -> IO VerifyResult
verifyCertChain (X509Store storeFptr) (X509Cert targetFptr) intermediates =
  withForeignPtr storeFptr $ \storePtr ->
    withForeignPtr targetFptr $ \targetPtr -> do
      -- Build STACK_OF(X509) for intermediates
      skPtr <- c_bssl_sk_X509_new_null
      if skPtr == nullPtr
        then return (VerifyFailed (-1) "sk_X509_new_null failed")
        else do
          -- Push all intermediate certs (check for allocation failure)
          pushResults <- mapM (\(X509Cert fp) -> withForeignPtr fp $ \cp ->
            c_bssl_sk_X509_push skPtr cp) intermediates
          if any (== 0) pushResults
            then do
              c_bssl_sk_X509_free skPtr
              mapM_ (\(X509Cert fp) -> touchForeignPtr fp) intermediates
              return (VerifyFailed (-1) "sk_X509_push allocation failed")
            else do
              -- Create and initialize X509_STORE_CTX
              result <- bracket c_X509_STORE_CTX_new
                                (\ctx -> if ctx /= nullPtr
                                           then c_X509_STORE_CTX_free ctx
                                           else return ())
                       $ \ctx -> do
                if ctx == nullPtr
                  then return (VerifyFailed (-1) "X509_STORE_CTX_new failed")
                  else do
                    rc <- c_X509_STORE_CTX_init ctx storePtr targetPtr skPtr
                    if rc /= 1
                      then return (VerifyFailed (-1) "X509_STORE_CTX_init failed")
                      else do
                        vrc <- c_X509_verify_cert ctx
                        if vrc == 1
                          then return VerifyOK
                          else do
                            errCode <- c_X509_STORE_CTX_get_error ctx
                            errStr <- c_X509_verify_cert_error_string (fromIntegral errCode)
                            errMsg <- if errStr == nullPtr
                                        then return "unknown"
                                        else peekCString errStr
                            return (VerifyFailed (fromIntegral errCode) errMsg)
              c_bssl_sk_X509_free skPtr
              -- Keep intermediate ForeignPtrs alive through verification
              mapM_ (\(X509Cert fp) -> touchForeignPtr fp) intermediates
              return result

------------------------------------------------------------------------
-- Feature 9: Certificate signature algorithm
------------------------------------------------------------------------

data SignatureAlgInfo = SignatureAlgInfo
  { sigAlgNID       :: Int
  , sigAlgShortName :: String
  , sigAlgLongName  :: String
  } deriving (Eq, Show)

-- | Get the signature algorithm information from a certificate.
-- Returns @Nothing@ if the NID is unknown.
certSignatureAlgorithm :: X509Cert -> IO (Maybe SignatureAlgInfo)
certSignatureAlgorithm (X509Cert fptr) =
  withForeignPtr fptr $ \certPtr -> do
    nid <- c_X509_get_signature_nid certPtr
    if nid <= 0
      then return Nothing
      else do
        snPtr <- c_OBJ_nid2sn nid
        lnPtr <- c_OBJ_nid2ln nid
        sn <- if snPtr == nullPtr then return "" else peekCString snPtr
        ln <- if lnPtr == nullPtr then return "" else peekCString lnPtr
        return (Just (SignatureAlgInfo (fromIntegral nid) sn ln))

------------------------------------------------------------------------
-- Feature 10: DN as DER bytes
------------------------------------------------------------------------

-- | Serialize the subject distinguished name to DER.
certSubjectDER :: X509Cert -> IO ByteString
certSubjectDER (X509Cert fptr) =
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_subject_name certPtr
    nameToDER namePtr

-- | Serialize the issuer distinguished name to DER.
certIssuerDER :: X509Cert -> IO ByteString
certIssuerDER (X509Cert fptr) =
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_issuer_name certPtr
    nameToDER namePtr

nameToDER :: Ptr X509_NAME -> IO ByteString
nameToDER namePtr = do
  len <- c_i2d_X509_NAME namePtr nullPtr
  if len <= 0
    then return BS.empty
    else do
      outFPtr <- BSI.mallocByteString (fromIntegral len)
      withForeignPtr outFPtr $ \outBuf ->
        alloca $ \outPtrPtr -> do
          poke outPtrPtr (castPtr outBuf)
          _ <- c_i2d_X509_NAME namePtr outPtrPtr
          return ()
      return (BSI.BS outFPtr (fromIntegral len))
