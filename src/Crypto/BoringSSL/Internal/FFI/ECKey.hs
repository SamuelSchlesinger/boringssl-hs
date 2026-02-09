{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.ECKey
  ( -- * Opaque types
    EC_KEY
  , EC_GROUP
  , EC_POINT
  , BIGNUM
    -- * EC_KEY lifecycle
  , c_EC_KEY_new_by_curve_name
  , c_EC_KEY_free
  , c_EC_KEY_free_funptr
  , c_EC_KEY_generate_key
    -- * EC_KEY accessors
  , c_EC_KEY_get0_group
  , c_EC_KEY_get0_public_key
  , c_EC_KEY_get0_private_key
  , c_EC_KEY_set_public_key
  , c_EC_KEY_set_private_key
  , c_EC_KEY_check_key
    -- * EC_GROUP
  , c_EC_group_p256
  , c_EC_group_p384
  , c_EC_group_p521
    -- * EC_POINT
  , c_EC_POINT_new
  , c_EC_POINT_free
  , c_EC_POINT_oct2point
  , c_EC_POINT_point2oct
    -- * BIGNUM
  , c_BN_new
  , c_BN_free
  , c_BN_set_word
  , c_BN_num_bytes
  , c_BN_bn2bin
  , c_BN_bn2bin_padded
  , c_BN_bin2bn
  , c_EC_GROUP_get_degree
    -- * EC_POINT arithmetic
  , c_EC_POINT_mul
  , c_EC_POINT_get_affine_coordinates_GFp
  ) where

import Foreign.C.Types
import Foreign.Ptr

-- Opaque types
data EC_KEY
data EC_GROUP
data EC_POINT
data BIGNUM

-- EC_KEY lifecycle

-- | EC_KEY *EC_KEY_new_by_curve_name(int nid)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_new_by_curve_name"
  c_EC_KEY_new_by_curve_name :: CInt -> IO (Ptr EC_KEY)

-- | void EC_KEY_free(EC_KEY *key)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_free"
  c_EC_KEY_free :: Ptr EC_KEY -> IO ()

-- | FunPtr for use as ForeignPtr finalizer
foreign import ccall unsafe "&EC_KEY_free"
  c_EC_KEY_free_funptr :: FunPtr (Ptr EC_KEY -> IO ())

-- | int EC_KEY_generate_key(EC_KEY *key)
foreign import capi safe "openssl/ec_key.h EC_KEY_generate_key"
  c_EC_KEY_generate_key :: Ptr EC_KEY -> IO CInt

-- EC_KEY accessors

-- | const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_get0_group"
  c_EC_KEY_get0_group :: Ptr EC_KEY -> IO (Ptr EC_GROUP)

-- | const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_get0_public_key"
  c_EC_KEY_get0_public_key :: Ptr EC_KEY -> IO (Ptr EC_POINT)

-- | const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_get0_private_key"
  c_EC_KEY_get0_private_key :: Ptr EC_KEY -> IO (Ptr BIGNUM)

-- | int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_set_public_key"
  c_EC_KEY_set_public_key :: Ptr EC_KEY -> Ptr EC_POINT -> IO CInt

-- | int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_set_private_key"
  c_EC_KEY_set_private_key :: Ptr EC_KEY -> Ptr BIGNUM -> IO CInt

-- | int EC_KEY_check_key(const EC_KEY *key)
foreign import capi unsafe "openssl/ec_key.h EC_KEY_check_key"
  c_EC_KEY_check_key :: Ptr EC_KEY -> IO CInt

-- EC_GROUP

-- | const EC_GROUP *EC_group_p256(void)
foreign import capi unsafe "openssl/ec.h EC_group_p256"
  c_EC_group_p256 :: IO (Ptr EC_GROUP)

-- | const EC_GROUP *EC_group_p384(void)
foreign import capi unsafe "openssl/ec.h EC_group_p384"
  c_EC_group_p384 :: IO (Ptr EC_GROUP)

-- | const EC_GROUP *EC_group_p521(void)
foreign import capi unsafe "openssl/ec.h EC_group_p521"
  c_EC_group_p521 :: IO (Ptr EC_GROUP)

-- EC_POINT

-- | EC_POINT *EC_POINT_new(const EC_GROUP *group)
foreign import capi unsafe "openssl/ec.h EC_POINT_new"
  c_EC_POINT_new :: Ptr EC_GROUP -> IO (Ptr EC_POINT)

-- | void EC_POINT_free(EC_POINT *point)
foreign import capi unsafe "openssl/ec.h EC_POINT_free"
  c_EC_POINT_free :: Ptr EC_POINT -> IO ()

-- | int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point,
--                          const uint8_t *buf, size_t len, BN_CTX *ctx)
foreign import capi unsafe "openssl/ec.h EC_POINT_oct2point"
  c_EC_POINT_oct2point :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr CUChar -> CSize -> Ptr () -> IO CInt

-- | size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point,
--                             point_conversion_form_t form, uint8_t *buf,
--                             size_t max_out, BN_CTX *ctx)
-- point_conversion_form_t: POINT_CONVERSION_UNCOMPRESSED = 4
foreign import capi unsafe "openssl/ec.h EC_POINT_point2oct"
  c_EC_POINT_point2oct :: Ptr EC_GROUP -> Ptr EC_POINT -> CInt -> Ptr CUChar -> CSize -> Ptr () -> IO CSize

-- BIGNUM

-- | BIGNUM *BN_new(void)
foreign import capi unsafe "openssl/bn.h BN_new"
  c_BN_new :: IO (Ptr BIGNUM)

-- | void BN_free(BIGNUM *bn)
foreign import capi unsafe "openssl/bn.h BN_free"
  c_BN_free :: Ptr BIGNUM -> IO ()

-- | int BN_set_word(BIGNUM *bn, BN_ULONG value)
foreign import capi unsafe "openssl/bn.h BN_set_word"
  c_BN_set_word :: Ptr BIGNUM -> CULong -> IO CInt

-- | unsigned BN_num_bytes(const BIGNUM *bn)
foreign import capi unsafe "openssl/bn.h BN_num_bytes"
  c_BN_num_bytes :: Ptr BIGNUM -> IO CUInt

-- | size_t BN_bn2bin(const BIGNUM *in, uint8_t *out)
foreign import capi unsafe "openssl/bn.h BN_bn2bin"
  c_BN_bn2bin :: Ptr BIGNUM -> Ptr CUChar -> IO CSize

-- | int BN_bn2bin_padded(uint8_t *out, size_t len, const BIGNUM *in)
foreign import capi unsafe "openssl/bn.h BN_bn2bin_padded"
  c_BN_bn2bin_padded :: Ptr CUChar -> CSize -> Ptr BIGNUM -> IO CInt

-- | unsigned EC_GROUP_get_degree(const EC_GROUP *group)
foreign import capi unsafe "openssl/ec.h EC_GROUP_get_degree"
  c_EC_GROUP_get_degree :: Ptr EC_GROUP -> IO CUInt

-- | BIGNUM *BN_bin2bn(const uint8_t *in, size_t len, BIGNUM *ret)
foreign import capi unsafe "openssl/bn.h BN_bin2bn"
  c_BN_bin2bn :: Ptr CUChar -> CSize -> Ptr BIGNUM -> IO (Ptr BIGNUM)

-- EC_POINT arithmetic

-- | int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r,
--                    const BIGNUM *n, const EC_POINT *q,
--                    const BIGNUM *m, BN_CTX *ctx)
-- To compute r = n * G (generator), pass q=NULL, m=NULL.
foreign import capi safe "openssl/ec.h EC_POINT_mul"
  c_EC_POINT_mul :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr () -> IO CInt

-- | int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
--     const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
foreign import capi unsafe "openssl/ec.h EC_POINT_get_affine_coordinates_GFp"
  c_EC_POINT_get_affine_coordinates_GFp
    :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr () -> IO CInt
