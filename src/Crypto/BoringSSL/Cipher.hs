-- | Symmetric cipher encryption and decryption.
--
-- Supports AES-128\/256 in CBC, CTR, ECB, and OFB modes.
-- CBC and ECB modes apply PKCS#7 padding automatically.
-- ECB mode uses no IV (pass 'Data.ByteString.empty' as the IV argument).
--
-- __WARNING:__ These ciphers do __NOT__ provide authentication or integrity
-- protection. An attacker can modify ciphertext without detection. Use the
-- "Crypto.BoringSSL.AEAD" module for authenticated encryption.
--
-- __WARNING:__ ECB mode ('AES128ECB', 'AES256ECB') is insecure for
-- general-purpose encryption. Identical plaintext blocks produce identical
-- ciphertext blocks, leaking patterns.
module Crypto.BoringSSL.Cipher
  ( -- * Algorithms
    CipherAlgorithm(..)
    -- * Encryption and decryption
  , encrypt
  , decrypt
    -- * Algorithm properties
  , cipherKeyLength
  , cipherIVLength
  , cipherBlockSize
  ) where

import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.Cipher

-- | Supported symmetric cipher algorithms.
data CipherAlgorithm
  = AES128CBC | AES256CBC
  | AES128CTR | AES256CTR
  | AES128ECB
    -- ^ __WARNING:__ ECB mode is insecure for general-purpose encryption.
    -- Identical plaintext blocks produce identical ciphertext blocks, leaking
    -- patterns. Consider using CBC, CTR, or preferably AEAD instead.
  | AES256ECB
    -- ^ __WARNING:__ ECB mode is insecure for general-purpose encryption.
    -- Identical plaintext blocks produce identical ciphertext blocks, leaking
    -- patterns. Consider using CBC, CTR, or preferably AEAD instead.
  | AES128OFB | AES256OFB
  deriving (Eq, Show)

-- | Get the C cipher pointer.
cipherPtr :: CipherAlgorithm -> Ptr EVP_CIPHER
cipherPtr AES128CBC = c_EVP_aes_128_cbc
cipherPtr AES256CBC = c_EVP_aes_256_cbc
cipherPtr AES128CTR = c_EVP_aes_128_ctr
cipherPtr AES256CTR = c_EVP_aes_256_ctr
cipherPtr AES128ECB = c_EVP_aes_128_ecb
cipherPtr AES256ECB = c_EVP_aes_256_ecb
cipherPtr AES128OFB = c_EVP_aes_128_ofb
cipherPtr AES256OFB = c_EVP_aes_256_ofb

-- | Expected key length in bytes.
cipherKeyLength :: CipherAlgorithm -> Int
cipherKeyLength AES128CBC = 16
cipherKeyLength AES256CBC = 32
cipherKeyLength AES128CTR = 16
cipherKeyLength AES256CTR = 32
cipherKeyLength AES128ECB = 16
cipherKeyLength AES256ECB = 32
cipherKeyLength AES128OFB = 16
cipherKeyLength AES256OFB = 32

-- | Expected IV length in bytes. ECB mode uses no IV (returns 0).
cipherIVLength :: CipherAlgorithm -> Int
cipherIVLength AES128ECB = 0
cipherIVLength AES256ECB = 0
cipherIVLength _ = 16

-- | Block size in bytes (1 for stream-like modes: CTR, OFB).
cipherBlockSize :: CipherAlgorithm -> Int
cipherBlockSize AES128CBC = 16
cipherBlockSize AES256CBC = 16
cipherBlockSize AES128CTR = 1
cipherBlockSize AES256CTR = 1
cipherBlockSize AES128ECB = 16
cipherBlockSize AES256ECB = 16
cipherBlockSize AES128OFB = 1
cipherBlockSize AES256OFB = 1

-- | Encrypt plaintext. CBC and ECB modes apply PKCS#7 padding automatically.
-- For ECB mode, pass an empty IV (@BS.empty@).
encrypt :: CipherAlgorithm -> ByteString -> ByteString -> ByteString
        -> IO (Either CryptoError ByteString)
encrypt algo key iv plaintext
  | BS.length key /= cipherKeyLength algo =
      return (Left (InvalidInput ("encrypt: key length " ++ show (BS.length key) ++ " does not match expected " ++ show (cipherKeyLength algo))))
  | BS.length iv /= cipherIVLength algo =
      return (Left (InvalidInput ("encrypt: IV length " ++ show (BS.length iv) ++ " does not match expected " ++ show (cipherIVLength algo))))
  | otherwise = withBoundThread $
      withByteString key $ \keyPtr _ ->
        withByteString plaintext $ \inPtr inLen -> do
        let ivAction f =
              if cipherIVLength algo == 0
                then f nullPtr
                else withByteString iv $ \ivPtr _ -> f ivPtr
        ivAction $ \ivPtr -> do
          let maxOutLen = fromIntegral inLen + (16 :: Int)
          fptr <- BSI.mallocByteString maxOutLen
          fmap (fmap (BSI.BS fptr)) $ withForeignPtr fptr $ \outPtr -> runExceptT $ do
            ctx <- bracketE c_EVP_CIPHER_CTX_new
                            (\c -> when (c /= nullPtr) (c_EVP_CIPHER_CTX_free c))
                            $ \c -> do
              _ <- nonNull (AllocationFailure "encrypt: EVP_CIPHER_CTX_new failed") c
              liftIO clearBoringSSLError
              rc1 <- liftIO $ c_EVP_EncryptInit_ex c (cipherPtr algo) nullPtr keyPtr ivPtr
              checkRCError "encrypt: EncryptInit failed" rc1
              allocaE $ \updateLenPtr -> allocaE $ \finalLenPtr -> do
                liftIO $ poke updateLenPtr 0
                liftIO $ poke finalLenPtr 0
                rc2 <- liftIO $ c_EVP_EncryptUpdate_ex c (castPtr outPtr) updateLenPtr
                         (fromIntegral maxOutLen) inPtr inLen
                checkRCError "encrypt: EncryptUpdate failed" rc2
                updateLen <- liftIO $ peek updateLenPtr
                let remaining = fromIntegral maxOutLen - updateLen
                rc3 <- liftIO $ c_EVP_EncryptFinal_ex2 c
                         (castPtr outPtr `plusPtr` fromIntegral updateLen)
                         finalLenPtr remaining
                checkRCError "encrypt: EncryptFinal failed" rc3
                finalLen <- liftIO $ peek finalLenPtr
                return (fromIntegral (updateLen + finalLen))
            return ctx

-- | Decrypt ciphertext. CBC and ECB modes remove PKCS#7 padding automatically.
-- For ECB mode, pass an empty IV (@BS.empty@).
-- Returns Left on failure (e.g. bad padding).
decrypt :: CipherAlgorithm -> ByteString -> ByteString -> ByteString
        -> IO (Either CryptoError ByteString)
decrypt algo key iv ciphertext
  | BS.length key /= cipherKeyLength algo =
      return (Left (InvalidInput ("decrypt: key length " ++ show (BS.length key) ++ " does not match expected " ++ show (cipherKeyLength algo))))
  | BS.length iv /= cipherIVLength algo =
      return (Left (InvalidInput ("decrypt: IV length " ++ show (BS.length iv) ++ " does not match expected " ++ show (cipherIVLength algo))))
  | otherwise = withBoundThread $
      withByteString key $ \keyPtr _ ->
        withByteString ciphertext $ \inPtr inLen -> do
        let ivAction f =
              if cipherIVLength algo == 0
                then f nullPtr
                else withByteString iv $ \ivPtr _ -> f ivPtr
        ivAction $ \ivPtr -> do
          let maxOutLen = fromIntegral inLen + (16 :: Int)
          fptr <- BSI.mallocByteString maxOutLen
          fmap (fmap (BSI.BS fptr)) $ withForeignPtr fptr $ \outPtr -> runExceptT $ do
            ctx <- bracketE c_EVP_CIPHER_CTX_new
                            (\c -> when (c /= nullPtr) (c_EVP_CIPHER_CTX_free c))
                            $ \c -> do
              _ <- nonNull (AllocationFailure "decrypt: EVP_CIPHER_CTX_new failed") c
              liftIO clearBoringSSLError
              rc1 <- liftIO $ c_EVP_DecryptInit_ex c (cipherPtr algo) nullPtr keyPtr ivPtr
              checkRCError "decrypt: decryption failed" rc1
              allocaE $ \updateLenPtr -> allocaE $ \finalLenPtr -> do
                liftIO $ poke updateLenPtr 0
                liftIO $ poke finalLenPtr 0
                rc2 <- liftIO $ c_EVP_DecryptUpdate_ex c (castPtr outPtr) updateLenPtr
                         (fromIntegral maxOutLen) inPtr inLen
                checkRCError "decrypt: decryption failed" rc2
                updateLen <- liftIO $ peek updateLenPtr
                let remaining = fromIntegral maxOutLen - updateLen
                rc3 <- liftIO $ c_EVP_DecryptFinal_ex2 c
                         (castPtr outPtr `plusPtr` fromIntegral updateLen)
                         finalLenPtr remaining
                checkRCError "decrypt: decryption failed" rc3
                finalLen <- liftIO $ peek finalLenPtr
                return (fromIntegral (updateLen + finalLen))
            return ctx
