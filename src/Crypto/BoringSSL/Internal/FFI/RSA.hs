{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.RSA
  ( -- * Opaque type
    RSA_C
    -- * Lifecycle
  , c_RSA_new
  , c_RSA_free
  , c_RSA_free_funptr
    -- * Key generation
  , c_RSA_generate_key_ex
    -- * Properties
  , c_RSA_size
  , c_RSA_bits
    -- * PKCS#1 v1.5 sign/verify
  , c_RSA_sign
  , c_RSA_verify
    -- * PSS sign/verify
  , c_RSA_sign_pss_mgf1
  , c_RSA_verify_pss_mgf1
    -- * OAEP encrypt/decrypt
  , c_RSA_encrypt
  , c_RSA_decrypt
    -- * Serialization
  , c_RSA_public_key_to_bytes
  , c_RSA_private_key_to_bytes
  , c_RSA_public_key_from_bytes
  , c_RSA_private_key_from_bytes
  ) where

import Crypto.BoringSSL.Internal.FFI.Digest (EVP_MD)
import Crypto.BoringSSL.Internal.FFI.ECKey (BIGNUM)
import Foreign.C.Types
import Foreign.Ptr

-- | Opaque type for RSA (named RSA_C to avoid clash with module name).
data RSA_C

-- Lifecycle

-- | RSA *RSA_new(void)
foreign import ccall unsafe "RSA_new"
  c_RSA_new :: IO (Ptr RSA_C)

-- | void RSA_free(RSA *rsa)
foreign import ccall unsafe "RSA_free"
  c_RSA_free :: Ptr RSA_C -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&RSA_free"
  c_RSA_free_funptr :: FunPtr (Ptr RSA_C -> IO ())

-- Key generation

-- | int RSA_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb)
-- This is imported as 'safe' (not 'unsafe') because RSA key generation
-- can take a significant amount of time and should not block the Haskell RTS.
foreign import ccall safe "RSA_generate_key_ex"
  c_RSA_generate_key_ex :: Ptr RSA_C -> CInt -> Ptr BIGNUM -> Ptr () -> IO CInt

-- Properties

-- | unsigned RSA_size(const RSA *rsa)
foreign import ccall unsafe "RSA_size"
  c_RSA_size :: Ptr RSA_C -> IO CUInt

-- | unsigned RSA_bits(const RSA *rsa)
foreign import ccall unsafe "RSA_bits"
  c_RSA_bits :: Ptr RSA_C -> IO CUInt

-- PKCS#1 v1.5 sign/verify

-- | int RSA_sign(int hash_nid, const uint8_t *digest, size_t digest_len,
--                uint8_t *out, unsigned *out_len, RSA *rsa)
foreign import ccall unsafe "RSA_sign"
  c_RSA_sign :: CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> Ptr CUInt -> Ptr RSA_C -> IO CInt

-- | int RSA_verify(int hash_nid, const uint8_t *digest, size_t digest_len,
--                  const uint8_t *sig, size_t sig_len, RSA *rsa)
foreign import ccall unsafe "RSA_verify"
  c_RSA_verify :: CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr RSA_C -> IO CInt

-- PSS sign/verify

-- | int RSA_sign_pss_mgf1(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
--                         const uint8_t *digest, size_t digest_len,
--                         const EVP_MD *md, const EVP_MD *mgf1_md, int salt_len)
foreign import ccall unsafe "RSA_sign_pss_mgf1"
  c_RSA_sign_pss_mgf1 :: Ptr RSA_C -> Ptr CSize -> Ptr CUChar -> CSize
                       -> Ptr CUChar -> CSize
                       -> Ptr EVP_MD -> Ptr EVP_MD -> CInt
                       -> IO CInt

-- | int RSA_verify_pss_mgf1(RSA *rsa, const uint8_t *digest, size_t digest_len,
--                           const EVP_MD *md, const EVP_MD *mgf1_md, int salt_len,
--                           const uint8_t *sig, size_t sig_len)
foreign import ccall unsafe "RSA_verify_pss_mgf1"
  c_RSA_verify_pss_mgf1 :: Ptr RSA_C -> Ptr CUChar -> CSize
                         -> Ptr EVP_MD -> Ptr EVP_MD -> CInt
                         -> Ptr CUChar -> CSize
                         -> IO CInt

-- OAEP encrypt/decrypt

-- | int RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
--                   const uint8_t *in, size_t in_len, int padding)
foreign import ccall unsafe "RSA_encrypt"
  c_RSA_encrypt :: Ptr RSA_C -> Ptr CSize -> Ptr CUChar -> CSize
                -> Ptr CUChar -> CSize -> CInt -> IO CInt

-- | int RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
--                   const uint8_t *in, size_t in_len, int padding)
foreign import ccall unsafe "RSA_decrypt"
  c_RSA_decrypt :: Ptr RSA_C -> Ptr CSize -> Ptr CUChar -> CSize
                -> Ptr CUChar -> CSize -> CInt -> IO CInt

-- Serialization

-- | int RSA_public_key_to_bytes(uint8_t **out_bytes, size_t *out_len, const RSA *rsa)
foreign import ccall unsafe "RSA_public_key_to_bytes"
  c_RSA_public_key_to_bytes :: Ptr (Ptr CUChar) -> Ptr CSize -> Ptr RSA_C -> IO CInt

-- | int RSA_private_key_to_bytes(uint8_t **out_bytes, size_t *out_len, const RSA *rsa)
foreign import ccall unsafe "RSA_private_key_to_bytes"
  c_RSA_private_key_to_bytes :: Ptr (Ptr CUChar) -> Ptr CSize -> Ptr RSA_C -> IO CInt

-- | RSA *RSA_public_key_from_bytes(const uint8_t *in, size_t in_len)
foreign import ccall unsafe "RSA_public_key_from_bytes"
  c_RSA_public_key_from_bytes :: Ptr CUChar -> CSize -> IO (Ptr RSA_C)

-- | RSA *RSA_private_key_from_bytes(const uint8_t *in, size_t in_len)
foreign import ccall unsafe "RSA_private_key_from_bytes"
  c_RSA_private_key_from_bytes :: Ptr CUChar -> CSize -> IO (Ptr RSA_C)
