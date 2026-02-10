{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.X509
  ( -- * Opaque types
    X509
  , X509_NAME
  , EVP_PKEY
  , ASN1_INTEGER
  , ASN1_TIME
  , X509_STORE
  , X509_STORE_CTX
  , BIO
  , BASIC_CONSTRAINTS
  , GENERAL_NAME
  , GENERAL_NAMES
  , ASN1_STRING
  , BIGNUM
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
  , c_EVP_PKEY_free_funptr
  , c_EVP_PKEY_id
  , c_EVP_PKEY_get0_RSA
  , c_EVP_PKEY_get0_EC_KEY
  , c_EVP_PKEY_get_raw_public_key
  , c_EVP_PKEY_get_raw_private_key
    -- * ASN1 helpers
  , c_ASN1_INTEGER_to_BN
  , c_ASN1_TIME_to_posix
    -- * BIGNUM helpers
  , c_BN_bn2hex
  , c_BN_free
    -- * Signature algorithm
  , c_X509_get_signature_nid
  , c_OBJ_nid2sn
  , c_OBJ_nid2ln
    -- * DN as DER
  , c_i2d_X509_NAME
    -- * Key usage
  , c_X509_get_key_usage
    -- * Extension access
  , c_X509_get_ext_d2i
    -- * BASIC_CONSTRAINTS helpers (C helpers)
  , c_bssl_basic_constraints_ca
  , c_bssl_basic_constraints_pathlen
  , c_BASIC_CONSTRAINTS_free
    -- * GENERAL_NAME helpers (C helpers)
  , c_bssl_general_name_type
  , c_bssl_general_name_data
  , c_bssl_sk_GENERAL_NAME_num
  , c_bssl_sk_GENERAL_NAME_value
  , c_GENERAL_NAMES_free
    -- * ASN1_STRING helpers (C helpers)
  , c_bssl_ASN1_STRING_get0_data
  , c_bssl_ASN1_STRING_length
    -- * X509_STORE
  , c_X509_STORE_new
  , c_X509_STORE_free
  , c_X509_STORE_free_funptr
  , c_X509_STORE_add_cert
    -- * X509_STORE_CTX
  , c_X509_STORE_CTX_new
  , c_X509_STORE_CTX_free
  , c_X509_STORE_CTX_init
  , c_X509_verify_cert
  , c_X509_STORE_CTX_get_error
  , c_X509_verify_cert_error_string
    -- * STACK_OF(X509) helpers (C helpers)
  , c_bssl_sk_X509_new_null
  , c_bssl_sk_X509_push
  , c_bssl_sk_X509_free
    -- * BIO
  , c_BIO_new_mem_buf
  , c_BIO_free
    -- * Private key loading
  , c_d2i_AutoPrivateKey
  , c_PEM_read_bio_PrivateKey
    -- * EC_GROUP curve name
  , c_EC_GROUP_get_curve_name
  ) where

import Data.Int (Int64)
import Foreign.C.Types
import Foreign.Ptr

import Crypto.BoringSSL.Internal.FFI.RSA (RSA_C)
import Crypto.BoringSSL.Internal.FFI.ECKey (EC_KEY, EC_GROUP)

-- Opaque types
data X509
data X509_NAME
data EVP_PKEY
data ASN1_INTEGER
data ASN1_TIME
data X509_STORE
data X509_STORE_CTX
data BIO
data BASIC_CONSTRAINTS
data GENERAL_NAME
data GENERAL_NAMES
data ASN1_STRING
data BIGNUM

------------------------------------------------------------------------
-- X.509 parsing and serialization
------------------------------------------------------------------------

-- | X509 *d2i_X509(X509 **out, const uint8_t **inp, long len)
foreign import capi unsafe "openssl/x509.h d2i_X509"
  c_d2i_X509
    :: Ptr (Ptr X509)
    -> Ptr (Ptr CUChar)
    -> CLong
    -> IO (Ptr X509)

-- | void X509_free(X509 *x509)
foreign import capi unsafe "openssl/x509.h X509_free"
  c_X509_free :: Ptr X509 -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&X509_free"
  c_X509_free_funptr :: FunPtr (Ptr X509 -> IO ())

-- | int i2d_X509(X509 *x509, uint8_t **outp)
foreign import capi unsafe "openssl/x509.h i2d_X509"
  c_i2d_X509
    :: Ptr X509
    -> Ptr (Ptr CUChar)
    -> IO CInt

------------------------------------------------------------------------
-- X.509 accessors
------------------------------------------------------------------------

foreign import capi unsafe "openssl/x509.h X509_get_subject_name"
  c_X509_get_subject_name :: Ptr X509 -> IO (Ptr X509_NAME)

foreign import capi unsafe "openssl/x509.h X509_get_issuer_name"
  c_X509_get_issuer_name :: Ptr X509 -> IO (Ptr X509_NAME)

foreign import capi unsafe "openssl/x509.h X509_NAME_oneline"
  c_X509_NAME_oneline
    :: Ptr X509_NAME -> Ptr CChar -> CInt -> IO (Ptr CChar)

foreign import capi unsafe "openssl/x509.h X509_get_version"
  c_X509_get_version :: Ptr X509 -> IO CLong

foreign import capi unsafe "openssl/x509.h X509_get0_serialNumber"
  c_X509_get0_serialNumber :: Ptr X509 -> IO (Ptr ASN1_INTEGER)

foreign import capi unsafe "openssl/x509.h X509_get0_notBefore"
  c_X509_get0_notBefore :: Ptr X509 -> IO (Ptr ASN1_TIME)

foreign import capi unsafe "openssl/x509.h X509_get0_notAfter"
  c_X509_get0_notAfter :: Ptr X509 -> IO (Ptr ASN1_TIME)

------------------------------------------------------------------------
-- X.509 verification
------------------------------------------------------------------------

foreign import capi unsafe "openssl/x509.h X509_verify"
  c_X509_verify :: Ptr X509 -> Ptr EVP_PKEY -> IO CInt

------------------------------------------------------------------------
-- EVP_PKEY
------------------------------------------------------------------------

foreign import capi unsafe "openssl/x509.h X509_get_pubkey"
  c_X509_get_pubkey :: Ptr X509 -> IO (Ptr EVP_PKEY)

foreign import capi unsafe "openssl/evp.h EVP_PKEY_free"
  c_EVP_PKEY_free :: Ptr EVP_PKEY -> IO ()

foreign import ccall unsafe "&EVP_PKEY_free"
  c_EVP_PKEY_free_funptr :: FunPtr (Ptr EVP_PKEY -> IO ())

-- | int EVP_PKEY_id(const EVP_PKEY *pkey)
foreign import capi unsafe "openssl/evp.h EVP_PKEY_id"
  c_EVP_PKEY_id :: Ptr EVP_PKEY -> IO CInt

-- | RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey)
-- Returns borrowed pointer. Do NOT free.
foreign import capi unsafe "openssl/evp.h EVP_PKEY_get0_RSA"
  c_EVP_PKEY_get0_RSA :: Ptr EVP_PKEY -> IO (Ptr RSA_C)

-- | EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)
-- Returns borrowed pointer. Do NOT free.
foreign import capi unsafe "openssl/evp.h EVP_PKEY_get0_EC_KEY"
  c_EVP_PKEY_get0_EC_KEY :: Ptr EVP_PKEY -> IO (Ptr EC_KEY)

-- | int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey,
--     uint8_t *out, size_t *out_len)
foreign import capi unsafe "openssl/evp.h EVP_PKEY_get_raw_public_key"
  c_EVP_PKEY_get_raw_public_key :: Ptr EVP_PKEY -> Ptr CUChar -> Ptr CSize -> IO CInt

-- | int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey,
--     uint8_t *out, size_t *out_len)
foreign import capi unsafe "openssl/evp.h EVP_PKEY_get_raw_private_key"
  c_EVP_PKEY_get_raw_private_key :: Ptr EVP_PKEY -> Ptr CUChar -> Ptr CSize -> IO CInt

------------------------------------------------------------------------
-- ASN1 helpers
------------------------------------------------------------------------

foreign import capi unsafe "openssl/asn1.h ASN1_INTEGER_to_BN"
  c_ASN1_INTEGER_to_BN :: Ptr ASN1_INTEGER -> Ptr BIGNUM -> IO (Ptr BIGNUM)

foreign import capi unsafe "openssl/asn1.h ASN1_TIME_to_posix"
  c_ASN1_TIME_to_posix :: Ptr ASN1_TIME -> Ptr Int64 -> IO CInt

------------------------------------------------------------------------
-- BIGNUM helpers
------------------------------------------------------------------------

foreign import capi unsafe "openssl/bn.h BN_bn2hex"
  c_BN_bn2hex :: Ptr BIGNUM -> IO (Ptr CChar)

foreign import capi unsafe "openssl/bn.h BN_free"
  c_BN_free :: Ptr BIGNUM -> IO ()

------------------------------------------------------------------------
-- Feature 9: Signature algorithm
------------------------------------------------------------------------

-- | int X509_get_signature_nid(const X509 *x509)
foreign import capi unsafe "openssl/x509.h X509_get_signature_nid"
  c_X509_get_signature_nid :: Ptr X509 -> IO CInt

-- | const char *OBJ_nid2sn(int nid)
foreign import capi unsafe "openssl/obj.h OBJ_nid2sn"
  c_OBJ_nid2sn :: CInt -> IO (Ptr CChar)

-- | const char *OBJ_nid2ln(int nid)
foreign import capi unsafe "openssl/obj.h OBJ_nid2ln"
  c_OBJ_nid2ln :: CInt -> IO (Ptr CChar)

------------------------------------------------------------------------
-- Feature 10: DN as DER
------------------------------------------------------------------------

-- | int i2d_X509_NAME(X509_NAME *name, uint8_t **outp)
foreign import capi unsafe "openssl/x509.h i2d_X509_NAME"
  c_i2d_X509_NAME :: Ptr X509_NAME -> Ptr (Ptr CUChar) -> IO CInt

------------------------------------------------------------------------
-- Feature 7: Key usage
------------------------------------------------------------------------

-- | uint32_t X509_get_key_usage(X509 *x509)
-- Returns bitmask of key usage flags. UINT32_MAX if not present.
foreign import capi unsafe "openssl/x509.h X509_get_key_usage"
  c_X509_get_key_usage :: Ptr X509 -> IO CUInt

-- | void *X509_get_ext_d2i(const X509 *x509, int nid, int *crit, int *idx)
foreign import capi unsafe "openssl/x509.h X509_get_ext_d2i"
  c_X509_get_ext_d2i :: Ptr X509 -> CInt -> Ptr CInt -> Ptr CInt -> IO (Ptr ())

------------------------------------------------------------------------
-- Feature 7: BASIC_CONSTRAINTS (via C helpers)
------------------------------------------------------------------------

foreign import capi unsafe "x509_helpers.h bssl_basic_constraints_ca"
  c_bssl_basic_constraints_ca :: Ptr BASIC_CONSTRAINTS -> IO CInt

foreign import capi unsafe "x509_helpers.h bssl_basic_constraints_pathlen"
  c_bssl_basic_constraints_pathlen :: Ptr BASIC_CONSTRAINTS -> IO (Ptr ASN1_INTEGER)

foreign import capi unsafe "openssl/x509v3.h BASIC_CONSTRAINTS_free"
  c_BASIC_CONSTRAINTS_free :: Ptr BASIC_CONSTRAINTS -> IO ()

------------------------------------------------------------------------
-- Feature 7: GENERAL_NAME (via C helpers)
------------------------------------------------------------------------

foreign import capi unsafe "x509_helpers.h bssl_general_name_type"
  c_bssl_general_name_type :: Ptr GENERAL_NAME -> IO CInt

-- | Returns the GENERAL_NAME data union pointer. Only valid as
-- Ptr ASN1_STRING for types GEN_EMAIL (1), GEN_DNS (2), GEN_URI (6),
-- GEN_IPADD (7). Callers must check bssl_general_name_type before
-- dereferencing.
foreign import capi unsafe "x509_helpers.h bssl_general_name_data"
  c_bssl_general_name_data :: Ptr GENERAL_NAME -> IO (Ptr ASN1_STRING)

foreign import capi unsafe "x509_helpers.h bssl_sk_GENERAL_NAME_num"
  c_bssl_sk_GENERAL_NAME_num :: Ptr GENERAL_NAMES -> IO CInt

foreign import capi unsafe "x509_helpers.h bssl_sk_GENERAL_NAME_value"
  c_bssl_sk_GENERAL_NAME_value :: Ptr GENERAL_NAMES -> CInt -> IO (Ptr GENERAL_NAME)

foreign import capi unsafe "openssl/x509v3.h GENERAL_NAMES_free"
  c_GENERAL_NAMES_free :: Ptr GENERAL_NAMES -> IO ()

------------------------------------------------------------------------
-- Feature 7: ASN1_STRING (via C helpers)
------------------------------------------------------------------------

foreign import capi unsafe "x509_helpers.h bssl_ASN1_STRING_get0_data"
  c_bssl_ASN1_STRING_get0_data :: Ptr ASN1_STRING -> IO (Ptr CUChar)

foreign import capi unsafe "x509_helpers.h bssl_ASN1_STRING_length"
  c_bssl_ASN1_STRING_length :: Ptr ASN1_STRING -> IO CInt

------------------------------------------------------------------------
-- Feature 8: X509_STORE
------------------------------------------------------------------------

foreign import capi unsafe "openssl/x509.h X509_STORE_new"
  c_X509_STORE_new :: IO (Ptr X509_STORE)

foreign import capi unsafe "openssl/x509.h X509_STORE_free"
  c_X509_STORE_free :: Ptr X509_STORE -> IO ()

foreign import ccall unsafe "&X509_STORE_free"
  c_X509_STORE_free_funptr :: FunPtr (Ptr X509_STORE -> IO ())

-- | int X509_STORE_add_cert(X509_STORE *store, X509 *x509)
foreign import capi unsafe "openssl/x509.h X509_STORE_add_cert"
  c_X509_STORE_add_cert :: Ptr X509_STORE -> Ptr X509 -> IO CInt

------------------------------------------------------------------------
-- Feature 8: X509_STORE_CTX
------------------------------------------------------------------------

foreign import capi unsafe "openssl/x509.h X509_STORE_CTX_new"
  c_X509_STORE_CTX_new :: IO (Ptr X509_STORE_CTX)

foreign import capi unsafe "openssl/x509.h X509_STORE_CTX_free"
  c_X509_STORE_CTX_free :: Ptr X509_STORE_CTX -> IO ()

-- | int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
--     X509 *x509, STACK_OF(X509) *chain)
foreign import capi unsafe "openssl/x509.h X509_STORE_CTX_init"
  c_X509_STORE_CTX_init
    :: Ptr X509_STORE_CTX -> Ptr X509_STORE -> Ptr X509 -> Ptr () -> IO CInt

-- | int X509_verify_cert(X509_STORE_CTX *ctx)
-- safe import: may do I/O
foreign import capi safe "openssl/x509.h X509_verify_cert"
  c_X509_verify_cert :: Ptr X509_STORE_CTX -> IO CInt

-- | int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx)
foreign import capi unsafe "openssl/x509.h X509_STORE_CTX_get_error"
  c_X509_STORE_CTX_get_error :: Ptr X509_STORE_CTX -> IO CInt

-- | const char *X509_verify_cert_error_string(long n)
foreign import capi unsafe "openssl/x509.h X509_verify_cert_error_string"
  c_X509_verify_cert_error_string :: CLong -> IO (Ptr CChar)

------------------------------------------------------------------------
-- Feature 8: STACK_OF(X509) helpers (C helpers)
------------------------------------------------------------------------

foreign import capi unsafe "x509_helpers.h bssl_sk_X509_new_null"
  c_bssl_sk_X509_new_null :: IO (Ptr ())

foreign import capi unsafe "x509_helpers.h bssl_sk_X509_push"
  c_bssl_sk_X509_push :: Ptr () -> Ptr X509 -> IO CInt

foreign import capi unsafe "x509_helpers.h bssl_sk_X509_free"
  c_bssl_sk_X509_free :: Ptr () -> IO ()

------------------------------------------------------------------------
-- Feature 11: BIO
------------------------------------------------------------------------

-- | BIO *BIO_new_mem_buf(const void *buf, ossl_ssize_t len)
-- The length parameter is ossl_ssize_t (ptrdiff_t), not int.
foreign import capi unsafe "openssl/bio.h BIO_new_mem_buf"
  c_BIO_new_mem_buf :: Ptr CUChar -> CPtrdiff -> IO (Ptr BIO)

-- | int BIO_free(BIO *bio)
foreign import capi unsafe "openssl/bio.h BIO_free"
  c_BIO_free :: Ptr BIO -> IO CInt

------------------------------------------------------------------------
-- Feature 11: Private key loading
------------------------------------------------------------------------

-- | EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **out, const uint8_t **inp, long len)
foreign import capi unsafe "openssl/evp.h d2i_AutoPrivateKey"
  c_d2i_AutoPrivateKey
    :: Ptr (Ptr EVP_PKEY) -> Ptr (Ptr CUChar) -> CLong -> IO (Ptr EVP_PKEY)

-- | EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
--     pem_password_cb *cb, void *u)
foreign import capi unsafe "openssl/pem.h PEM_read_bio_PrivateKey"
  c_PEM_read_bio_PrivateKey
    :: Ptr BIO -> Ptr (Ptr EVP_PKEY) -> Ptr () -> Ptr () -> IO (Ptr EVP_PKEY)

------------------------------------------------------------------------
-- Feature 11: EC_GROUP curve name
------------------------------------------------------------------------

-- | int EC_GROUP_get_curve_name(const EC_GROUP *group)
foreign import capi unsafe "openssl/ec.h EC_GROUP_get_curve_name"
  c_EC_GROUP_get_curve_name :: Ptr EC_GROUP -> IO CInt
