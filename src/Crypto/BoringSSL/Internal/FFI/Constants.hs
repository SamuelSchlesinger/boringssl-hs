{-# LANGUAGE CApiFFI #-}
-- | Compile-time derived constants from BoringSSL headers.
--
-- NID values and struct sizes are obtained via C helper functions rather than
-- being hardcoded, so they automatically stay in sync with the BoringSSL
-- version compiled into the library.
module Crypto.BoringSSL.Internal.FFI.Constants
  ( -- * EC curve NIDs
    nidX962Prime256v1
  , nidSecp384r1
  , nidSecp521r1
    -- * Digest algorithm NIDs
  , nidSHA1
  , nidSHA224
  , nidSHA256
  , nidSHA384
  , nidSHA512
  , nidSHA512_256
  , nidMD5
    -- * ML-KEM struct sizes
  , sizeofMLKEM768PrivateKey
  , sizeofMLKEM768PublicKey
  , sizeofMLKEM1024PrivateKey
  , sizeofMLKEM1024PublicKey
    -- * ML-DSA struct sizes
  , sizeofMLDSA44PrivateKey
  , sizeofMLDSA44PublicKey
  , sizeofMLDSA65PrivateKey
  , sizeofMLDSA65PublicKey
  , sizeofMLDSA87PrivateKey
  , sizeofMLDSA87PublicKey
    -- * X-Wing struct sizes
  , sizeofXWINGPrivateKey
  ) where

import Foreign.C.Types (CInt(..), CSize(..))
import System.IO.Unsafe (unsafePerformIO)

------------------------------------------------------------------------
-- EC curve NIDs
------------------------------------------------------------------------

foreign import capi unsafe "constants.h bssl_NID_X9_62_prime256v1"
  c_bssl_NID_X9_62_prime256v1 :: IO CInt

-- | NID for the P-256 curve (NID_X9_62_prime256v1).
nidX962Prime256v1 :: CInt
nidX962Prime256v1 = unsafePerformIO c_bssl_NID_X9_62_prime256v1
{-# NOINLINE nidX962Prime256v1 #-}

foreign import capi unsafe "constants.h bssl_NID_secp384r1"
  c_bssl_NID_secp384r1 :: IO CInt

-- | NID for the P-384 curve (NID_secp384r1).
nidSecp384r1 :: CInt
nidSecp384r1 = unsafePerformIO c_bssl_NID_secp384r1
{-# NOINLINE nidSecp384r1 #-}

foreign import capi unsafe "constants.h bssl_NID_secp521r1"
  c_bssl_NID_secp521r1 :: IO CInt

-- | NID for the P-521 curve (NID_secp521r1).
nidSecp521r1 :: CInt
nidSecp521r1 = unsafePerformIO c_bssl_NID_secp521r1
{-# NOINLINE nidSecp521r1 #-}

------------------------------------------------------------------------
-- Digest algorithm NIDs
------------------------------------------------------------------------

foreign import capi unsafe "constants.h bssl_NID_sha1"
  c_bssl_NID_sha1 :: IO CInt

-- | NID for SHA-1.
nidSHA1 :: CInt
nidSHA1 = unsafePerformIO c_bssl_NID_sha1
{-# NOINLINE nidSHA1 #-}

foreign import capi unsafe "constants.h bssl_NID_sha224"
  c_bssl_NID_sha224 :: IO CInt

-- | NID for SHA-224.
nidSHA224 :: CInt
nidSHA224 = unsafePerformIO c_bssl_NID_sha224
{-# NOINLINE nidSHA224 #-}

foreign import capi unsafe "constants.h bssl_NID_sha256"
  c_bssl_NID_sha256 :: IO CInt

-- | NID for SHA-256.
nidSHA256 :: CInt
nidSHA256 = unsafePerformIO c_bssl_NID_sha256
{-# NOINLINE nidSHA256 #-}

foreign import capi unsafe "constants.h bssl_NID_sha384"
  c_bssl_NID_sha384 :: IO CInt

-- | NID for SHA-384.
nidSHA384 :: CInt
nidSHA384 = unsafePerformIO c_bssl_NID_sha384
{-# NOINLINE nidSHA384 #-}

foreign import capi unsafe "constants.h bssl_NID_sha512"
  c_bssl_NID_sha512 :: IO CInt

-- | NID for SHA-512.
nidSHA512 :: CInt
nidSHA512 = unsafePerformIO c_bssl_NID_sha512
{-# NOINLINE nidSHA512 #-}

foreign import capi unsafe "constants.h bssl_NID_sha512_256"
  c_bssl_NID_sha512_256 :: IO CInt

-- | NID for SHA-512/256.
nidSHA512_256 :: CInt
nidSHA512_256 = unsafePerformIO c_bssl_NID_sha512_256
{-# NOINLINE nidSHA512_256 #-}

foreign import capi unsafe "constants.h bssl_NID_md5"
  c_bssl_NID_md5 :: IO CInt

-- | NID for MD5.
nidMD5 :: CInt
nidMD5 = unsafePerformIO c_bssl_NID_md5
{-# NOINLINE nidMD5 #-}

------------------------------------------------------------------------
-- ML-KEM struct sizes
------------------------------------------------------------------------

foreign import capi unsafe "constants.h bssl_sizeof_MLKEM768_private_key"
  c_bssl_sizeof_MLKEM768_private_key :: IO CSize

-- | @sizeof(struct MLKEM768_private_key)@, derived from the BoringSSL header.
sizeofMLKEM768PrivateKey :: Int
sizeofMLKEM768PrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLKEM768_private_key)
{-# NOINLINE sizeofMLKEM768PrivateKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLKEM768_public_key"
  c_bssl_sizeof_MLKEM768_public_key :: IO CSize

-- | @sizeof(struct MLKEM768_public_key)@, derived from the BoringSSL header.
sizeofMLKEM768PublicKey :: Int
sizeofMLKEM768PublicKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLKEM768_public_key)
{-# NOINLINE sizeofMLKEM768PublicKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLKEM1024_private_key"
  c_bssl_sizeof_MLKEM1024_private_key :: IO CSize

-- | @sizeof(struct MLKEM1024_private_key)@, derived from the BoringSSL header.
sizeofMLKEM1024PrivateKey :: Int
sizeofMLKEM1024PrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLKEM1024_private_key)
{-# NOINLINE sizeofMLKEM1024PrivateKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLKEM1024_public_key"
  c_bssl_sizeof_MLKEM1024_public_key :: IO CSize

-- | @sizeof(struct MLKEM1024_public_key)@, derived from the BoringSSL header.
sizeofMLKEM1024PublicKey :: Int
sizeofMLKEM1024PublicKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLKEM1024_public_key)
{-# NOINLINE sizeofMLKEM1024PublicKey #-}

------------------------------------------------------------------------
-- ML-DSA struct sizes
------------------------------------------------------------------------

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA44_private_key"
  c_bssl_sizeof_MLDSA44_private_key :: IO CSize

-- | @sizeof(struct MLDSA44_private_key)@, derived from the BoringSSL header.
sizeofMLDSA44PrivateKey :: Int
sizeofMLDSA44PrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA44_private_key)
{-# NOINLINE sizeofMLDSA44PrivateKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA44_public_key"
  c_bssl_sizeof_MLDSA44_public_key :: IO CSize

-- | @sizeof(struct MLDSA44_public_key)@, derived from the BoringSSL header.
sizeofMLDSA44PublicKey :: Int
sizeofMLDSA44PublicKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA44_public_key)
{-# NOINLINE sizeofMLDSA44PublicKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA65_private_key"
  c_bssl_sizeof_MLDSA65_private_key :: IO CSize

-- | @sizeof(struct MLDSA65_private_key)@, derived from the BoringSSL header.
sizeofMLDSA65PrivateKey :: Int
sizeofMLDSA65PrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA65_private_key)
{-# NOINLINE sizeofMLDSA65PrivateKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA65_public_key"
  c_bssl_sizeof_MLDSA65_public_key :: IO CSize

-- | @sizeof(struct MLDSA65_public_key)@, derived from the BoringSSL header.
sizeofMLDSA65PublicKey :: Int
sizeofMLDSA65PublicKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA65_public_key)
{-# NOINLINE sizeofMLDSA65PublicKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA87_private_key"
  c_bssl_sizeof_MLDSA87_private_key :: IO CSize

-- | @sizeof(struct MLDSA87_private_key)@, derived from the BoringSSL header.
sizeofMLDSA87PrivateKey :: Int
sizeofMLDSA87PrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA87_private_key)
{-# NOINLINE sizeofMLDSA87PrivateKey #-}

foreign import capi unsafe "constants.h bssl_sizeof_MLDSA87_public_key"
  c_bssl_sizeof_MLDSA87_public_key :: IO CSize

-- | @sizeof(struct MLDSA87_public_key)@, derived from the BoringSSL header.
sizeofMLDSA87PublicKey :: Int
sizeofMLDSA87PublicKey = fromIntegral (unsafePerformIO c_bssl_sizeof_MLDSA87_public_key)
{-# NOINLINE sizeofMLDSA87PublicKey #-}

------------------------------------------------------------------------
-- X-Wing struct sizes
------------------------------------------------------------------------

foreign import capi unsafe "constants.h bssl_sizeof_XWING_private_key"
  c_bssl_sizeof_XWING_private_key :: IO CSize

-- | @sizeof(struct XWING_private_key)@, derived from the BoringSSL header.
sizeofXWINGPrivateKey :: Int
sizeofXWINGPrivateKey = fromIntegral (unsafePerformIO c_bssl_sizeof_XWING_private_key)
{-# NOINLINE sizeofXWINGPrivateKey #-}
