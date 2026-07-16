{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.BoringSSL.Internal.FFI.TrustToken
  ( -- * Opaque types
    TRUST_TOKEN_METHOD
  , TRUST_TOKEN_CLIENT
  , TRUST_TOKEN_ISSUER
  , TRUST_TOKEN
  , STACK_TRUST_TOKEN
    -- * Constants
  , trustTokenMaxPrivateKeySize
  , trustTokenMaxPublicKeySize
    -- * Method selectors
  , c_TRUST_TOKEN_experiment_v2_voprf
  , c_TRUST_TOKEN_experiment_v2_pmb
  , c_TRUST_TOKEN_pst_v1_voprf
  , c_TRUST_TOKEN_pst_v1_pmb
    -- * Key generation
  , c_TRUST_TOKEN_generate_key
    -- * Token
  , c_TRUST_TOKEN_new
  , c_TRUST_TOKEN_free
    -- * Client
  , c_TRUST_TOKEN_CLIENT_new
  , c_TRUST_TOKEN_CLIENT_free
  , c_TRUST_TOKEN_CLIENT_free_funptr
  , c_TRUST_TOKEN_CLIENT_add_key
  , c_TRUST_TOKEN_CLIENT_begin_issuance
  , c_TRUST_TOKEN_CLIENT_finish_issuance
  , c_TRUST_TOKEN_CLIENT_begin_redemption
  , c_TRUST_TOKEN_CLIENT_finish_redemption
    -- * Issuer
  , c_TRUST_TOKEN_ISSUER_new
  , c_TRUST_TOKEN_ISSUER_free
  , c_TRUST_TOKEN_ISSUER_free_funptr
  , c_TRUST_TOKEN_ISSUER_add_key
  , c_TRUST_TOKEN_ISSUER_issue
  , c_TRUST_TOKEN_ISSUER_redeem
    -- * Stack helpers (from cbits)
  , c_boringssl_sk_TRUST_TOKEN_num
  , c_boringssl_sk_TRUST_TOKEN_value
  , c_boringssl_sk_TRUST_TOKEN_pop_free
    -- * Token field accessors (from cbits)
  , c_boringssl_TRUST_TOKEN_data
  , c_boringssl_TRUST_TOKEN_len
  ) where

import Foreign.C.Types
import Foreign.Ptr
import Data.Word (Word32, Word64, Word8)

-- Opaque types
data TRUST_TOKEN_METHOD
data TRUST_TOKEN_CLIENT
data TRUST_TOKEN_ISSUER
data TRUST_TOKEN
data STACK_TRUST_TOKEN

-- Constants
trustTokenMaxPrivateKeySize :: Int
trustTokenMaxPrivateKeySize = 512

trustTokenMaxPublicKeySize :: Int
trustTokenMaxPublicKeySize = 512

-- Method selectors

-- | const TRUST_TOKEN_METHOD *TRUST_TOKEN_experiment_v2_voprf(void)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_experiment_v2_voprf"
  c_TRUST_TOKEN_experiment_v2_voprf :: Ptr TRUST_TOKEN_METHOD

-- | const TRUST_TOKEN_METHOD *TRUST_TOKEN_experiment_v2_pmb(void)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_experiment_v2_pmb"
  c_TRUST_TOKEN_experiment_v2_pmb :: Ptr TRUST_TOKEN_METHOD

-- | const TRUST_TOKEN_METHOD *TRUST_TOKEN_pst_v1_voprf(void)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_pst_v1_voprf"
  c_TRUST_TOKEN_pst_v1_voprf :: Ptr TRUST_TOKEN_METHOD

-- | const TRUST_TOKEN_METHOD *TRUST_TOKEN_pst_v1_pmb(void)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_pst_v1_pmb"
  c_TRUST_TOKEN_pst_v1_pmb :: Ptr TRUST_TOKEN_METHOD

-- Key generation

-- | int TRUST_TOKEN_generate_key(
--     const TRUST_TOKEN_METHOD *method,
--     uint8_t *out_priv_key, size_t *out_priv_key_len, size_t max_priv_key_len,
--     uint8_t *out_pub_key, size_t *out_pub_key_len, size_t max_pub_key_len,
--     uint32_t id)
foreign import capi safe "openssl/trust_token.h TRUST_TOKEN_generate_key"
  c_TRUST_TOKEN_generate_key
    :: Ptr TRUST_TOKEN_METHOD
    -> Ptr CUChar -> Ptr CSize -> CSize
    -> Ptr CUChar -> Ptr CSize -> CSize
    -> Word32
    -> IO CInt

-- Token

-- | TRUST_TOKEN *TRUST_TOKEN_new(const uint8_t *data, size_t len)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_new"
  c_TRUST_TOKEN_new :: Ptr CUChar -> CSize -> IO (Ptr TRUST_TOKEN)

-- | void TRUST_TOKEN_free(TRUST_TOKEN *token)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_free"
  c_TRUST_TOKEN_free :: Ptr TRUST_TOKEN -> IO ()

-- Client

-- | TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(
--     const TRUST_TOKEN_METHOD *method, size_t max_batchsize)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_new"
  c_TRUST_TOKEN_CLIENT_new :: Ptr TRUST_TOKEN_METHOD -> CSize
                           -> IO (Ptr TRUST_TOKEN_CLIENT)

-- | void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_free"
  c_TRUST_TOKEN_CLIENT_free :: Ptr TRUST_TOKEN_CLIENT -> IO ()

-- | FunPtr for TRUST_TOKEN_CLIENT_free finalizer
foreign import ccall unsafe "&TRUST_TOKEN_CLIENT_free"
  c_TRUST_TOKEN_CLIENT_free_funptr :: FunPtr (Ptr TRUST_TOKEN_CLIENT -> IO ())

-- | int TRUST_TOKEN_CLIENT_add_key(
--     TRUST_TOKEN_CLIENT *ctx, size_t *out_key_index,
--     const uint8_t *key, size_t key_len)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_add_key"
  c_TRUST_TOKEN_CLIENT_add_key
    :: Ptr TRUST_TOKEN_CLIENT -> Ptr CSize -> Ptr CUChar -> CSize -> IO CInt

-- | int TRUST_TOKEN_CLIENT_begin_issuance(
--     TRUST_TOKEN_CLIENT *ctx, uint8_t **out, size_t *out_len, size_t count)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_begin_issuance"
  c_TRUST_TOKEN_CLIENT_begin_issuance
    :: Ptr TRUST_TOKEN_CLIENT -> Ptr (Ptr CUChar) -> Ptr CSize -> CSize
    -> IO CInt

-- | STACK_OF(TRUST_TOKEN) *TRUST_TOKEN_CLIENT_finish_issuance(
--     TRUST_TOKEN_CLIENT *ctx, size_t *out_key_index,
--     const uint8_t *response, size_t response_len)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_finish_issuance"
  c_TRUST_TOKEN_CLIENT_finish_issuance
    :: Ptr TRUST_TOKEN_CLIENT -> Ptr CSize -> Ptr CUChar -> CSize
    -> IO (Ptr STACK_TRUST_TOKEN)

-- | int TRUST_TOKEN_CLIENT_begin_redemption(
--     TRUST_TOKEN_CLIENT *ctx, uint8_t **out, size_t *out_len,
--     const TRUST_TOKEN *token, const uint8_t *data, size_t data_len,
--     uint64_t time)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_begin_redemption"
  c_TRUST_TOKEN_CLIENT_begin_redemption
    :: Ptr TRUST_TOKEN_CLIENT -> Ptr (Ptr CUChar) -> Ptr CSize
    -> Ptr TRUST_TOKEN -> Ptr CUChar -> CSize -> Word64 -> IO CInt

-- | int TRUST_TOKEN_CLIENT_finish_redemption(
--     TRUST_TOKEN_CLIENT *ctx, uint8_t **out_rr, size_t *out_rr_len,
--     uint8_t **out_sig, size_t *out_sig_len,
--     const uint8_t *response, size_t response_len)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_CLIENT_finish_redemption"
  c_TRUST_TOKEN_CLIENT_finish_redemption
    :: Ptr TRUST_TOKEN_CLIENT -> Ptr (Ptr CUChar) -> Ptr CSize
    -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr CUChar -> CSize -> IO CInt

-- Issuer

-- | TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(
--     const TRUST_TOKEN_METHOD *method, size_t max_batchsize)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_ISSUER_new"
  c_TRUST_TOKEN_ISSUER_new :: Ptr TRUST_TOKEN_METHOD -> CSize
                           -> IO (Ptr TRUST_TOKEN_ISSUER)

-- | void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_ISSUER_free"
  c_TRUST_TOKEN_ISSUER_free :: Ptr TRUST_TOKEN_ISSUER -> IO ()

-- | FunPtr for TRUST_TOKEN_ISSUER_free finalizer
foreign import ccall unsafe "&TRUST_TOKEN_ISSUER_free"
  c_TRUST_TOKEN_ISSUER_free_funptr :: FunPtr (Ptr TRUST_TOKEN_ISSUER -> IO ())

-- | int TRUST_TOKEN_ISSUER_add_key(
--     TRUST_TOKEN_ISSUER *ctx, const uint8_t *key, size_t key_len)
foreign import capi unsafe "openssl/trust_token.h TRUST_TOKEN_ISSUER_add_key"
  c_TRUST_TOKEN_ISSUER_add_key
    :: Ptr TRUST_TOKEN_ISSUER -> Ptr CUChar -> CSize -> IO CInt

-- | int TRUST_TOKEN_ISSUER_issue(
--     const TRUST_TOKEN_ISSUER *ctx, uint8_t **out, size_t *out_len,
--     size_t *out_tokens_issued, const uint8_t *request, size_t request_len,
--     uint32_t public_metadata, uint8_t private_metadata, size_t max_issuance)
-- Uses safe FFI as token issuance involves expensive crypto operations.
foreign import capi safe "openssl/trust_token.h TRUST_TOKEN_ISSUER_issue"
  c_TRUST_TOKEN_ISSUER_issue
    :: Ptr TRUST_TOKEN_ISSUER -> Ptr (Ptr CUChar) -> Ptr CSize
    -> Ptr CSize -> Ptr CUChar -> CSize
    -> Word32 -> Word8 -> CSize -> IO CInt

-- | int TRUST_TOKEN_ISSUER_redeem(
--     const TRUST_TOKEN_ISSUER *ctx, uint32_t *out_public, uint8_t *out_private,
--     TRUST_TOKEN **out_token, uint8_t **out_client_data,
--     size_t *out_client_data_len, const uint8_t *request, size_t request_len)
-- Uses safe FFI as token redemption involves expensive crypto operations.
foreign import capi safe "openssl/trust_token.h TRUST_TOKEN_ISSUER_redeem"
  c_TRUST_TOKEN_ISSUER_redeem
    :: Ptr TRUST_TOKEN_ISSUER -> Ptr Word32 -> Ptr Word8
    -> Ptr (Ptr TRUST_TOKEN) -> Ptr (Ptr CUChar) -> Ptr CSize
    -> Ptr CUChar -> CSize -> IO CInt

-- Stack helpers (from cbits/trust_token_helpers.c)

-- | size_t boringssl_sk_TRUST_TOKEN_num(const STACK_OF(TRUST_TOKEN) *sk)
foreign import capi unsafe "trust_token_helpers.h boringssl_sk_TRUST_TOKEN_num"
  c_boringssl_sk_TRUST_TOKEN_num :: Ptr STACK_TRUST_TOKEN -> IO CSize

-- | TRUST_TOKEN *boringssl_sk_TRUST_TOKEN_value(
--     const STACK_OF(TRUST_TOKEN) *sk, size_t i)
foreign import capi unsafe "trust_token_helpers.h boringssl_sk_TRUST_TOKEN_value"
  c_boringssl_sk_TRUST_TOKEN_value :: Ptr STACK_TRUST_TOKEN -> CSize
                                   -> IO (Ptr TRUST_TOKEN)

-- | void boringssl_sk_TRUST_TOKEN_pop_free(STACK_OF(TRUST_TOKEN) *sk)
foreign import capi unsafe "trust_token_helpers.h boringssl_sk_TRUST_TOKEN_pop_free"
  c_boringssl_sk_TRUST_TOKEN_pop_free :: Ptr STACK_TRUST_TOKEN -> IO ()

-- Token field accessors (from cbits/trust_token_helpers.c)

-- | const uint8_t *boringssl_TRUST_TOKEN_data(const TRUST_TOKEN *token)
foreign import capi unsafe "trust_token_helpers.h boringssl_TRUST_TOKEN_data"
  c_boringssl_TRUST_TOKEN_data :: Ptr TRUST_TOKEN -> IO (Ptr CUChar)

-- | size_t boringssl_TRUST_TOKEN_len(const TRUST_TOKEN *token)
foreign import capi unsafe "trust_token_helpers.h boringssl_TRUST_TOKEN_len"
  c_boringssl_TRUST_TOKEN_len :: Ptr TRUST_TOKEN -> IO CSize
