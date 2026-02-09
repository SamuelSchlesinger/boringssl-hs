-- | Authenticated encryption with associated data (AEAD).
--
-- Supports AES-GCM (128\/192\/256), ChaCha20-Poly1305, XChaCha20-Poly1305,
-- AES-GCM-SIV, AES-CTR-HMAC-SHA256, AES-EAX, and AES-CCM variants.
-- Use 'seal' to encrypt and 'open' to decrypt.
module Crypto.BoringSSL.AEAD
  ( -- * Algorithms
    AEADAlgorithm(..)
    -- * Context
  , AEADCtx
  , CryptoError(..)
  , newAEADCtx
    -- * Encryption and decryption
  , seal
  , open
    -- * Algorithm properties
  , keyLength
  , nonceLength
  , maxOverhead
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Control.Exception (mask_)
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI

-- | Supported AEAD algorithms.
data AEADAlgorithm
  = AES128GCM | AES192GCM | AES256GCM
  | ChaCha20Poly1305 | XChaCha20Poly1305
  | AES128GCMSIV | AES256GCMSIV
  | AES128CtrHmacSha256 | AES256CtrHmacSha256
  | AES128EAX | AES256EAX
  | AES128CCMBluetooth | AES128CCMBluetooth8 | AES128CCMMatter
  deriving (Eq, Show)

-- | An AEAD context wrapping a BoringSSL EVP_AEAD_CTX.
-- Automatically freed when garbage collected.
data AEADCtx = AEADCtx !AEADAlgorithm !(ForeignPtr EVP_AEAD_CTX)

-- | Get the C pointer for an AEAD algorithm.
aeadPtr :: AEADAlgorithm -> Ptr EVP_AEAD
aeadPtr AES128GCM            = c_EVP_aead_aes_128_gcm
aeadPtr AES192GCM            = c_EVP_aead_aes_192_gcm
aeadPtr AES256GCM            = c_EVP_aead_aes_256_gcm
aeadPtr ChaCha20Poly1305     = c_EVP_aead_chacha20_poly1305
aeadPtr XChaCha20Poly1305    = c_EVP_aead_xchacha20_poly1305
aeadPtr AES128GCMSIV         = c_EVP_aead_aes_128_gcm_siv
aeadPtr AES256GCMSIV         = c_EVP_aead_aes_256_gcm_siv
aeadPtr AES128CtrHmacSha256  = c_EVP_aead_aes_128_ctr_hmac_sha256
aeadPtr AES256CtrHmacSha256  = c_EVP_aead_aes_256_ctr_hmac_sha256
aeadPtr AES128EAX            = c_EVP_aead_aes_128_eax
aeadPtr AES256EAX            = c_EVP_aead_aes_256_eax
aeadPtr AES128CCMBluetooth   = c_EVP_aead_aes_128_ccm_bluetooth
aeadPtr AES128CCMBluetooth8  = c_EVP_aead_aes_128_ccm_bluetooth_8
aeadPtr AES128CCMMatter      = c_EVP_aead_aes_128_ccm_matter

-- | Create a new AEAD context for the given algorithm and key.
-- The key length must match the algorithm's expected key length.
-- Uses the default tag length (pass 0 to EVP_AEAD_CTX_new).
newAEADCtx :: AEADAlgorithm -> ByteString -> IO (Either CryptoError AEADCtx)
newAEADCtx algo key = do
  let aead = aeadPtr algo
      expectedKeyLen = keyLength algo
  if BS.length key /= expectedKeyLen
    then return $ Left $ InvalidInput $
           "newAEADCtx: key length " ++ show (BS.length key)
           ++ " does not match expected " ++ show expectedKeyLen
    else withByteString key $ \keyPtr keyLen -> mask_ $ do
      ctx <- c_EVP_AEAD_CTX_new aead keyPtr keyLen 0
      if ctx == nullPtr
        then do
          merr <- getBoringSSLError
          case merr of
            Just e  -> return (Left e)
            Nothing -> return (Left (AllocationFailure "newAEADCtx: EVP_AEAD_CTX_new returned NULL"))
        else do
          fptr <- newForeignPtr c_EVP_AEAD_CTX_free_funptr ctx
          return (Right (AEADCtx algo fptr))

-- | Encrypt and authenticate plaintext.
--
-- @seal ctx nonce plaintext ad@ encrypts @plaintext@ with the given
-- @nonce@ and additional data @ad@, returning the ciphertext (which
-- includes the authentication tag appended).
seal :: AEADCtx -> ByteString -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
seal (AEADCtx algo fptr) nonce plaintext ad =
  withForeignPtr fptr $ \ctx ->
  withByteString nonce $ \noncePtr nonceLen ->
  withByteString plaintext $ \inPtr inLen ->
  withByteString ad $ \adPtr adLen -> do
    let maxOutLen = inLen + fromIntegral (maxOverhead algo)
    outFPtr <- BSI.mallocByteString (fromIntegral maxOutLen)
    alloca $ \outLenPtr -> do
      poke outLenPtr 0
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_AEAD_CTX_seal ctx (castPtr outPtr) outLenPtr maxOutLen
          noncePtr nonceLen inPtr inLen adPtr adLen
      if rc == 1
        then do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))
        else do
          merr <- getBoringSSLError
          case merr of
            Just e  -> return (Left e)
            Nothing -> return (Left (OperationFailed "seal failed"))

-- | Decrypt and verify ciphertext.
--
-- @open ctx nonce ciphertext ad@ decrypts @ciphertext@ (which includes
-- the authentication tag) with the given @nonce@ and additional data @ad@.
-- Returns 'Left' if authentication fails.
open :: AEADCtx -> ByteString -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
open (AEADCtx _algo fptr) nonce ciphertext ad =
  withForeignPtr fptr $ \ctx ->
  withByteString nonce $ \noncePtr nonceLen ->
  withByteString ciphertext $ \inPtr inLen ->
  withByteString ad $ \adPtr adLen -> do
    let maxOutLen = inLen  -- plaintext is at most as long as ciphertext
    outFPtr <- BSI.mallocByteString (fromIntegral maxOutLen)
    alloca $ \outLenPtr -> do
      poke outLenPtr 0
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_AEAD_CTX_open ctx (castPtr outPtr) outLenPtr maxOutLen
          noncePtr nonceLen inPtr inLen adPtr adLen
      if rc == 1
        then do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))
        else do
          merr <- getBoringSSLError
          case merr of
            Just e  -> return (Left e)
            Nothing -> return (Left (OperationFailed "open failed: authentication error"))

-- | Query the expected key length for an AEAD algorithm.
keyLength :: AEADAlgorithm -> Int
keyLength = fromIntegral . c_EVP_AEAD_key_length . aeadPtr

-- | Query the expected nonce length for an AEAD algorithm.
nonceLength :: AEADAlgorithm -> Int
nonceLength = fromIntegral . c_EVP_AEAD_nonce_length . aeadPtr

-- | Query the maximum overhead (tag size) for an AEAD algorithm.
maxOverhead :: AEADAlgorithm -> Int
maxOverhead = fromIntegral . c_EVP_AEAD_max_overhead . aeadPtr
