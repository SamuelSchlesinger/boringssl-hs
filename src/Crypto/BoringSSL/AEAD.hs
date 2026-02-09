module Crypto.BoringSSL.AEAD
  ( AEADAlgorithm(..)
  , AEADCtx
  , BoringSSLError(..)
  , newAEADCtx
  , seal
  , open
  , keyLength
  , nonceLength
  , maxOverhead
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI

-- | Supported AEAD algorithms.
data AEADAlgorithm = AES128GCM | AES256GCM | ChaCha20Poly1305
  deriving (Eq, Show)

-- | An AEAD context wrapping a BoringSSL EVP_AEAD_CTX.
-- Automatically freed when garbage collected.
data AEADCtx = AEADCtx !AEADAlgorithm !(ForeignPtr EVP_AEAD_CTX)

-- | Get the C pointer for an AEAD algorithm.
aeadPtr :: AEADAlgorithm -> Ptr EVP_AEAD
aeadPtr AES128GCM        = c_EVP_aead_aes_128_gcm
aeadPtr AES256GCM        = c_EVP_aead_aes_256_gcm
aeadPtr ChaCha20Poly1305 = c_EVP_aead_chacha20_poly1305

-- | Create a new AEAD context for the given algorithm and key.
-- The key length must match the algorithm's expected key length.
-- Uses the default tag length (pass 0 to EVP_AEAD_CTX_new).
newAEADCtx :: AEADAlgorithm -> ByteString -> IO AEADCtx
newAEADCtx algo key = do
  let aead = aeadPtr algo
      expectedKeyLen = keyLength algo
  if BS.length key /= expectedKeyLen
    then fail $ "newAEADCtx: key length " ++ show (BS.length key)
             ++ " does not match expected " ++ show expectedKeyLen
    else withByteString key $ \keyPtr keyLen -> do
      ctx <- c_EVP_AEAD_CTX_new aead keyPtr keyLen 0
      if ctx == nullPtr
        then do
          merr <- getBoringSSLError
          case merr of
            Just e  -> fail (show e)
            Nothing -> fail "newAEADCtx: EVP_AEAD_CTX_new returned NULL"
        else do
          fptr <- newForeignPtr c_EVP_AEAD_CTX_free_funptr ctx
          return (AEADCtx algo fptr)

-- | Encrypt and authenticate plaintext.
--
-- @seal ctx nonce plaintext ad@ encrypts @plaintext@ with the given
-- @nonce@ and additional data @ad@, returning the ciphertext (which
-- includes the authentication tag appended).
seal :: AEADCtx -> ByteString -> ByteString -> ByteString -> IO (Either BoringSSLError ByteString)
seal (AEADCtx algo fptr) nonce plaintext ad =
  withForeignPtr fptr $ \ctx ->
  withByteString nonce $ \noncePtr nonceLen ->
  withByteString plaintext $ \inPtr inLen ->
  withByteString ad $ \adPtr adLen -> do
    let overhead = maxOverhead algo
        maxOutLen = fromIntegral (fromIntegral inLen + overhead :: Int) :: CSize
    outFPtr <- BSI.mallocByteString (fromIntegral maxOutLen)
    alloca $ \outLenPtr -> do
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
            Nothing -> return (Left (BoringSSLError 0 "seal failed"))

-- | Decrypt and verify ciphertext.
--
-- @open ctx nonce ciphertext ad@ decrypts @ciphertext@ (which includes
-- the authentication tag) with the given @nonce@ and additional data @ad@.
-- Returns 'Left' if authentication fails.
open :: AEADCtx -> ByteString -> ByteString -> ByteString -> IO (Either BoringSSLError ByteString)
open (AEADCtx _algo fptr) nonce ciphertext ad =
  withForeignPtr fptr $ \ctx ->
  withByteString nonce $ \noncePtr nonceLen ->
  withByteString ciphertext $ \inPtr inLen ->
  withByteString ad $ \adPtr adLen -> do
    let maxOutLen = inLen  -- plaintext is at most as long as ciphertext
    outFPtr <- BSI.mallocByteString (fromIntegral maxOutLen)
    alloca $ \outLenPtr -> do
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
            Nothing -> return (Left (BoringSSLError 0 "open failed: authentication error"))

-- | Query the expected key length for an AEAD algorithm.
keyLength :: AEADAlgorithm -> Int
keyLength = fromIntegral . c_EVP_AEAD_key_length . aeadPtr

-- | Query the expected nonce length for an AEAD algorithm.
nonceLength :: AEADAlgorithm -> Int
nonceLength = fromIntegral . c_EVP_AEAD_nonce_length . aeadPtr

-- | Query the maximum overhead (tag size) for an AEAD algorithm.
maxOverhead :: AEADAlgorithm -> Int
maxOverhead = fromIntegral . c_EVP_AEAD_max_overhead . aeadPtr
