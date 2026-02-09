{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.X509
  ( -- * Opaque types
    X509
  , X509_NAME
  , EVP_PKEY
    -- * X.509 parsing and serialization
  , c_d2i_X509
  , c_X509_free
  , c_X509_free_funptr
  , c_i2d_X509
    -- * X.509 accessors
  , c_X509_get_subject_name
  , c_X509_get_issuer_name
  , c_X509_NAME_oneline
    -- * EVP_PKEY
  , c_X509_get_pubkey
  , c_EVP_PKEY_free
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data X509
data X509_NAME
data EVP_PKEY

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

-- | EVP_PKEY *X509_get_pubkey(X509 *x509)
-- Extract the public key from the certificate. The caller must free it.
foreign import ccall unsafe "X509_get_pubkey"
  c_X509_get_pubkey :: Ptr X509 -> IO (Ptr EVP_PKEY)

-- | void EVP_PKEY_free(EVP_PKEY *pkey)
foreign import ccall unsafe "EVP_PKEY_free"
  c_EVP_PKEY_free :: Ptr EVP_PKEY -> IO ()
