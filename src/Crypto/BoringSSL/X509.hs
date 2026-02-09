-- | X.509 certificate parsing and inspection.
--
-- Provides DER and PEM parsing, DER serialization, name accessors,
-- version, serial number, validity times, and self-signed verification
-- for X.509 certificates using BoringSSL.
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
  , BoringSSLError(..)
  ) where

import Control.Exception (bracket, mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Data.Int (Int64)
import Foreign.C.String
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Array
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_free)
import Crypto.BoringSSL.Internal.FFI.X509
import qualified Crypto.BoringSSL.PEM as PEM

-- | An X.509 certificate. Automatically freed when garbage collected.
newtype X509Cert = X509Cert (ForeignPtr X509)

-- | Parse a DER-encoded X.509 certificate.
-- Returns 'Left' if parsing fails.
parseDER :: ByteString -> Either BoringSSLError X509Cert
parseDER bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    alloca $ \inpPtr -> do
      poke inpPtr dataPtr
      alloca $ \outPtr -> do
        poke outPtr nullPtr
        mask_ $ do
          cert <- c_d2i_X509 outPtr inpPtr (fromIntegral dataLen)
          if cert == nullPtr
            then return (Left (BoringSSLError 0 "X509.parseDER: failed to parse DER"))
            else do
              fptr <- newForeignPtr c_X509_free_funptr cert
              return (Right (X509Cert fptr))
{-# NOINLINE parseDER #-}

-- | Parse a PEM-encoded X.509 certificate.
-- Extracts the DER data between BEGIN\/END CERTIFICATE markers,
-- base64-decodes it, and parses the resulting DER.
-- Returns 'Left' if the PEM format is invalid or the certificate
-- cannot be parsed.
parsePEM :: ByteString -> Either BoringSSLError X509Cert
parsePEM pem =
  case PEM.pemDecode pem of
    Right ("CERTIFICATE", der) -> parseDER der
    Right (label, _) -> Left (BoringSSLError 0 ("X509.parsePEM: expected CERTIFICATE, got " ++ label))
    Left err -> Left err

-- | Serialize an X.509 certificate to DER encoding.
toDER :: X509Cert -> ByteString
toDER (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    -- First call with NULL to get length
    len <- c_i2d_X509 certPtr nullPtr
    if len <= 0
      then fail "X509.toDER: i2d_X509 failed to compute length"
      else do
        -- Second call to write
        outFPtr <- BSI.mallocByteString (fromIntegral len)
        withForeignPtr outFPtr $ \outBuf -> do
          alloca $ \outPtrPtr -> do
            poke outPtrPtr (castPtr outBuf)
            actualLen <- c_i2d_X509 certPtr outPtrPtr
            if actualLen <= 0
              then fail "X509.toDER: i2d_X509 failed to serialize"
              else return (BSI.BS outFPtr (fromIntegral actualLen))
{-# NOINLINE toDER #-}

-- | Get the subject name of an X.509 certificate as a human-readable string.
subjectName :: X509Cert -> String
subjectName (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_subject_name certPtr
    if namePtr == nullPtr
      then return ""
      else allocaArray 256 $ \buf -> do
        result <- c_X509_NAME_oneline namePtr buf 256
        if result == nullPtr
          then return ""
          else peekCString buf
{-# NOINLINE subjectName #-}

-- | Get the issuer name of an X.509 certificate as a human-readable string.
issuerName :: X509Cert -> String
issuerName (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    namePtr <- c_X509_get_issuer_name certPtr
    if namePtr == nullPtr
      then return ""
      else allocaArray 256 $ \buf -> do
        result <- c_X509_NAME_oneline namePtr buf 256
        if result == nullPtr
          then return ""
          else peekCString buf
{-# NOINLINE issuerName #-}

-- | Get the certificate version as a human-friendly number.
-- Returns 1, 2, or 3 (corresponding to the internal values 0, 1, 2).
version :: X509Cert -> Int
version (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    v <- c_X509_get_version certPtr
    return (fromIntegral v + 1)
{-# NOINLINE version #-}

-- | Get the certificate serial number as a hexadecimal string.
-- Uses the chain: X509_get0_serialNumber -> ASN1_INTEGER_to_BN -> BN_bn2hex.
-- Returns an empty string if any conversion step fails.
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

-- | Get the notBefore validity time as a POSIX timestamp (seconds since epoch).
-- Returns 'Left' if the time cannot be converted.
notBefore :: X509Cert -> Either BoringSSLError Int64
notBefore (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    timePtr <- c_X509_get0_notBefore certPtr
    if timePtr == nullPtr
      then return (Left (BoringSSLError 0 "X509.notBefore: no notBefore time"))
      else alloca $ \outPtr -> do
        rc <- c_ASN1_TIME_to_posix timePtr outPtr
        if rc == 1
          then do
            t <- peek outPtr
            return (Right t)
          else return (Left (BoringSSLError 0 "X509.notBefore: time conversion failed"))
{-# NOINLINE notBefore #-}

-- | Get the notAfter validity time as a POSIX timestamp (seconds since epoch).
-- Returns 'Left' if the time cannot be converted.
notAfter :: X509Cert -> Either BoringSSLError Int64
notAfter (X509Cert fptr) = unsafePerformIO $
  withForeignPtr fptr $ \certPtr -> do
    timePtr <- c_X509_get0_notAfter certPtr
    if timePtr == nullPtr
      then return (Left (BoringSSLError 0 "X509.notAfter: no notAfter time"))
      else alloca $ \outPtr -> do
        rc <- c_ASN1_TIME_to_posix timePtr outPtr
        if rc == 1
          then do
            t <- peek outPtr
            return (Right t)
          else return (Left (BoringSSLError 0 "X509.notAfter: time conversion failed"))
{-# NOINLINE notAfter #-}

-- | Verify that a certificate is validly self-signed.
-- Extracts the certificate's public key and uses it to verify the
-- certificate's signature. Returns 'True' if the signature is valid.
--
-- Note: This only checks the cryptographic signature, not the full
-- certificate chain or validity period.
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
