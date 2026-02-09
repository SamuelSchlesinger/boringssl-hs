{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.X509
  ( -- * Opaque types
    X509
  , X509_NAME
  , EVP_PKEY
  , ASN1_INTEGER
  , ASN1_TIME
    -- * X.509 parsing and serialization
  , c_d2i_X509
  , c_X509_free
  , c_X509_free_funptr
  , c_i2d_X509
    -- * X.509 accessors
  , c_X509_get_subject_name
  , c_X509_get_issuer_name
  , c_X509_NAME_oneline
  , c_X509_get_version
  , c_X509_get0_serialNumber
  , c_X509_get0_notBefore
  , c_X509_get0_notAfter
    -- * X.509 verification
  , c_X509_verify
    -- * EVP_PKEY
  , c_X509_get_pubkey
  , c_EVP_PKEY_free
    -- * ASN1 helpers
  , c_ASN1_INTEGER_to_BN
  , c_ASN1_TIME_to_posix
    -- * BIGNUM helpers
  , c_BN_bn2hex
  , c_BN_free
  ) where

import Data.Int (Int64)
import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data X509
data X509_NAME
data EVP_PKEY
data ASN1_INTEGER
data ASN1_TIME

-- | X509 *d2i_X509(X509 **out, const uint8_t **inp, long len)
-- Parse a DER-encoded X.509 certificate. If *out is NULL, allocates a new X509.
-- Returns the certificate or NULL on error.
foreign import ccall unsafe "d2i_X509"
  c_d2i_X509
    :: Ptr (Ptr X509)     -- out (can point to NULL)
    -> Ptr (Ptr CUChar)   -- inp (pointer to pointer into DER data)
    -> CLong              -- len
    -> IO (Ptr X509)

-- | void X509_free(X509 *x509)
foreign import ccall unsafe "X509_free"
  c_X509_free :: Ptr X509 -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&X509_free"
  c_X509_free_funptr :: FunPtr (Ptr X509 -> IO ())

-- | int i2d_X509(X509 *x509, uint8_t **outp)
-- Serialize an X509 to DER. If outp is NULL, returns the length needed.
-- If *outp is NULL, allocates and writes. Otherwise writes to *outp and advances it.
-- Returns the length on success or a negative value on error.
foreign import ccall unsafe "i2d_X509"
  c_i2d_X509
    :: Ptr X509          -- x509
    -> Ptr (Ptr CUChar)  -- outp
    -> IO CInt

-- | X509_NAME *X509_get_subject_name(const X509 *x509)
-- Returns the subject name. The returned pointer is internal and must not be freed.
foreign import ccall unsafe "X509_get_subject_name"
  c_X509_get_subject_name :: Ptr X509 -> IO (Ptr X509_NAME)

-- | X509_NAME *X509_get_issuer_name(const X509 *x509)
-- Returns the issuer name. The returned pointer is internal and must not be freed.
foreign import ccall unsafe "X509_get_issuer_name"
  c_X509_get_issuer_name :: Ptr X509 -> IO (Ptr X509_NAME)

-- | char *X509_NAME_oneline(const X509_NAME *name, char *buf, int size)
-- Writes a human-readable form of the name to buf. Returns buf on success.
foreign import ccall unsafe "X509_NAME_oneline"
  c_X509_NAME_oneline
    :: Ptr X509_NAME    -- name
    -> Ptr CChar        -- buf
    -> CInt             -- size
    -> IO (Ptr CChar)

-- | long X509_get_version(const X509 *x509)
-- Returns 0, 1, or 2 for v1, v2, v3.
foreign import ccall unsafe "X509_get_version"
  c_X509_get_version :: Ptr X509 -> IO CLong

-- | const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x509)
-- Returns the serial number. The returned pointer is internal and must not be freed.
foreign import ccall unsafe "X509_get0_serialNumber"
  c_X509_get0_serialNumber :: Ptr X509 -> IO (Ptr ASN1_INTEGER)

-- | const ASN1_TIME *X509_get0_notBefore(const X509 *x509)
-- Returns the notBefore time. The returned pointer is internal.
foreign import ccall unsafe "X509_get0_notBefore"
  c_X509_get0_notBefore :: Ptr X509 -> IO (Ptr ASN1_TIME)

-- | const ASN1_TIME *X509_get0_notAfter(const X509 *x509)
-- Returns the notAfter time. The returned pointer is internal.
foreign import ccall unsafe "X509_get0_notAfter"
  c_X509_get0_notAfter :: Ptr X509 -> IO (Ptr ASN1_TIME)

-- | int X509_verify(X509 *x509, EVP_PKEY *pkey)
-- Checks that x509 has a valid signature by pkey. Returns 1 if valid, 0 otherwise.
foreign import ccall unsafe "X509_verify"
  c_X509_verify :: Ptr X509 -> Ptr EVP_PKEY -> IO CInt

-- | EVP_PKEY *X509_get_pubkey(X509 *x509)
-- Extract the public key from the certificate. The caller must free it.
foreign import ccall unsafe "X509_get_pubkey"
  c_X509_get_pubkey :: Ptr X509 -> IO (Ptr EVP_PKEY)

-- | void EVP_PKEY_free(EVP_PKEY *pkey)
foreign import ccall unsafe "EVP_PKEY_free"
  c_EVP_PKEY_free :: Ptr EVP_PKEY -> IO ()

-- ASN1 helpers

-- | BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn)
-- Converts an ASN1_INTEGER to a BIGNUM. If bn is NULL, allocates a new BIGNUM.
-- Returns the BIGNUM on success, NULL on error. Caller must free if bn was NULL.
foreign import ccall unsafe "ASN1_INTEGER_to_BN"
  c_ASN1_INTEGER_to_BN :: Ptr ASN1_INTEGER -> Ptr a -> IO (Ptr a)

-- | int ASN1_TIME_to_posix(const ASN1_TIME *t, int64_t *out)
-- Converts an ASN1_TIME to a POSIX timestamp. Returns 1 on success, 0 on failure.
foreign import ccall unsafe "ASN1_TIME_to_posix"
  c_ASN1_TIME_to_posix :: Ptr ASN1_TIME -> Ptr Int64 -> IO CInt

-- BIGNUM helpers

-- | char *BN_bn2hex(const BIGNUM *bn)
-- Returns an allocated NUL-terminated hex string. Caller must OPENSSL_free it.
foreign import ccall unsafe "BN_bn2hex"
  c_BN_bn2hex :: Ptr a -> IO (Ptr CChar)

-- | void BN_free(BIGNUM *bn)
foreign import ccall unsafe "BN_free"
  c_BN_free :: Ptr a -> IO ()
