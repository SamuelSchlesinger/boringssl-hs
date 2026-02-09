-- | X.509 certificate parsing and inspection.
--
-- Provides DER parsing, DER serialization, and name accessors
-- for X.509 certificates using BoringSSL.
module Crypto.BoringSSL.X509
  ( X509Cert
  , parseDER
  , toDER
  , subjectName
  , issuerName
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.String
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Array
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.X509

-- | An X.509 certificate. Automatically freed when garbage collected.
newtype X509Cert = X509Cert (ForeignPtr X509)

-- | Parse a DER-encoded X.509 certificate.
-- Returns 'Nothing' if parsing fails.
parseDER :: ByteString -> Maybe X509Cert
parseDER bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    alloca $ \inpPtr -> do
      poke inpPtr dataPtr
      alloca $ \outPtr -> do
        poke outPtr nullPtr
        cert <- c_d2i_X509 outPtr inpPtr (fromIntegral dataLen)
        if cert == nullPtr
          then return Nothing
          else do
            fptr <- newForeignPtr c_X509_free_funptr cert
            return (Just (X509Cert fptr))
{-# NOINLINE parseDER #-}

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
