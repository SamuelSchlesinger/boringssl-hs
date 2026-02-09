module Crypto.BoringSSL.Internal.Digest
  ( Algorithm(..)
  , evpMD
  , digestSize
  , algorithmNID
  ) where

import Foreign.C.Types (CInt)
import Foreign.Ptr (Ptr)

import Crypto.BoringSSL.Internal.FFI.Digest

-- | Supported hash algorithms.
data Algorithm = SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA512_256 | MD5 | BLAKE2b256
  deriving (Eq, Show)

-- | Map a hash algorithm to its EVP_MD pointer.
evpMD :: Algorithm -> Ptr EVP_MD
evpMD SHA1       = c_EVP_sha1
evpMD SHA224     = c_EVP_sha224
evpMD SHA256     = c_EVP_sha256
evpMD SHA384     = c_EVP_sha384
evpMD SHA512     = c_EVP_sha512
evpMD SHA512_256 = c_EVP_sha512_256
evpMD MD5        = c_EVP_md5
evpMD BLAKE2b256 = c_EVP_blake2b256

-- | Output size in bytes for each algorithm.
digestSize :: Algorithm -> Int
digestSize SHA1       = 20
digestSize SHA224     = 28
digestSize SHA256     = 32
digestSize SHA384     = 48
digestSize SHA512     = 64
digestSize SHA512_256 = 32
digestSize MD5        = 16
digestSize BLAKE2b256 = 32

-- | NID value for each algorithm (used by RSA_sign etc.).
-- Returns 'Nothing' for algorithms that have no NID (e.g. BLAKE2b256),
-- which cannot be used with NID-based operations like RSA PKCS#1 v1.5.
--
-- These values are from BoringSSL's @nid.h@ header. If BoringSSL is updated,
-- verify these constants still match. Ideally these would be derived via
-- hsc2hs at compile time.
algorithmNID :: Algorithm -> Maybe CInt
algorithmNID SHA1       = Just 64   -- NID_sha1
algorithmNID SHA224     = Just 675  -- NID_sha224
algorithmNID SHA256     = Just 672  -- NID_sha256
algorithmNID SHA384     = Just 673  -- NID_sha384
algorithmNID SHA512     = Just 674  -- NID_sha512
algorithmNID SHA512_256 = Just 962  -- NID_sha512_256
algorithmNID MD5        = Just 4    -- NID_md5
algorithmNID BLAKE2b256 = Nothing   -- BLAKE2b256 has no NID in BoringSSL
