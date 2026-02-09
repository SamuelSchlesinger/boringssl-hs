{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.Digest
  ( -- * Opaque types
    EVP_MD
  , EVP_MD_CTX
    -- * One-shot hash functions
  , c_SHA1
  , c_SHA224
  , c_SHA256
  , c_SHA384
  , c_SHA512
  , c_SHA512_256
  , c_MD5
  , c_BLAKE2B256
    -- * EVP_MD selectors
  , c_EVP_sha1
  , c_EVP_sha224
  , c_EVP_sha256
  , c_EVP_sha384
  , c_EVP_sha512
  , c_EVP_sha512_256
  , c_EVP_md5
  , c_EVP_blake2b256
    -- * Streaming digest
  , c_EVP_MD_CTX_new
  , c_EVP_MD_CTX_free
  , c_EVP_MD_CTX_free_funptr
  , c_EVP_DigestInit_ex
  , c_EVP_DigestUpdate
  , c_EVP_DigestFinal_ex
  , c_EVP_MD_CTX_copy_ex
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- | Opaque type for EVP_MD (message digest algorithm descriptor).
data EVP_MD

-- | Opaque type for EVP_MD_CTX (streaming digest context).
data EVP_MD_CTX

-- One-shot hash functions

-- | uint8_t *SHA1(const uint8_t *data, size_t len, uint8_t out[20])
foreign import capi unsafe "openssl/sha.h SHA1"
  c_SHA1 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA224(const uint8_t *data, size_t len, uint8_t out[28])
foreign import capi unsafe "openssl/sha.h SHA224"
  c_SHA224 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t out[32])
foreign import capi unsafe "openssl/sha.h SHA256"
  c_SHA256 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA384(const uint8_t *data, size_t len, uint8_t out[48])
foreign import capi unsafe "openssl/sha.h SHA384"
  c_SHA384 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA512(const uint8_t *data, size_t len, uint8_t out[64])
foreign import capi unsafe "openssl/sha.h SHA512"
  c_SHA512 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *SHA512_256(const uint8_t *data, size_t len, uint8_t out[32])
foreign import capi unsafe "openssl/sha.h SHA512_256"
  c_SHA512_256 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | uint8_t *MD5(const uint8_t *data, size_t len, uint8_t out[16])
foreign import capi unsafe "openssl/md5.h MD5"
  c_MD5 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO (Ptr CUChar)

-- | void BLAKE2B256(const uint8_t *data, size_t len, uint8_t out[32])
foreign import capi unsafe "openssl/blake2.h BLAKE2B256"
  c_BLAKE2B256 :: Ptr CUChar -> CSize -> Ptr CUChar -> IO ()

-- EVP_MD selectors (pure, return const pointer)

-- | const EVP_MD *EVP_sha1(void)
foreign import capi unsafe "openssl/digest.h EVP_sha1"
  c_EVP_sha1 :: Ptr EVP_MD

-- | const EVP_MD *EVP_sha224(void)
foreign import capi unsafe "openssl/digest.h EVP_sha224"
  c_EVP_sha224 :: Ptr EVP_MD

-- | const EVP_MD *EVP_sha256(void)
foreign import capi unsafe "openssl/digest.h EVP_sha256"
  c_EVP_sha256 :: Ptr EVP_MD

-- | const EVP_MD *EVP_sha384(void)
foreign import capi unsafe "openssl/digest.h EVP_sha384"
  c_EVP_sha384 :: Ptr EVP_MD

-- | const EVP_MD *EVP_sha512(void)
foreign import capi unsafe "openssl/digest.h EVP_sha512"
  c_EVP_sha512 :: Ptr EVP_MD

-- | const EVP_MD *EVP_sha512_256(void)
foreign import capi unsafe "openssl/digest.h EVP_sha512_256"
  c_EVP_sha512_256 :: Ptr EVP_MD

-- | const EVP_MD *EVP_md5(void)
foreign import capi unsafe "openssl/digest.h EVP_md5"
  c_EVP_md5 :: Ptr EVP_MD

-- | const EVP_MD *EVP_blake2b256(void)
foreign import capi unsafe "openssl/digest.h EVP_blake2b256"
  c_EVP_blake2b256 :: Ptr EVP_MD

-- Streaming digest context

-- | EVP_MD_CTX *EVP_MD_CTX_new(void)
foreign import capi unsafe "openssl/digest.h EVP_MD_CTX_new"
  c_EVP_MD_CTX_new :: IO (Ptr EVP_MD_CTX)

-- | void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
foreign import capi unsafe "openssl/digest.h EVP_MD_CTX_free"
  c_EVP_MD_CTX_free :: Ptr EVP_MD_CTX -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&EVP_MD_CTX_free"
  c_EVP_MD_CTX_free_funptr :: FunPtr (Ptr EVP_MD_CTX -> IO ())

-- | int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *engine)
foreign import capi unsafe "openssl/digest.h EVP_DigestInit_ex"
  c_EVP_DigestInit_ex :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> Ptr () -> IO CInt

-- | int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len)
foreign import capi unsafe "openssl/digest.h EVP_DigestUpdate"
  c_EVP_DigestUpdate :: Ptr EVP_MD_CTX -> Ptr CUChar -> CSize -> IO CInt

-- | int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, uint8_t *md_out, unsigned int *out_size)
foreign import capi unsafe "openssl/digest.h EVP_DigestFinal_ex"
  c_EVP_DigestFinal_ex :: Ptr EVP_MD_CTX -> Ptr CUChar -> Ptr CUInt -> IO CInt

-- | int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
foreign import capi unsafe "openssl/digest.h EVP_MD_CTX_copy_ex"
  c_EVP_MD_CTX_copy_ex :: Ptr EVP_MD_CTX -> Ptr EVP_MD_CTX -> IO CInt
