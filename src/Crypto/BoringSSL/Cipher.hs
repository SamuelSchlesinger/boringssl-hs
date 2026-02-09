-- | Symmetric cipher encryption and decryption.
--
-- Supports AES-128\/256 in CBC, CTR, ECB, and OFB modes.
-- CBC and ECB modes apply PKCS#7 padding automatically.
-- ECB mode uses no IV (pass 'Data.ByteString.empty' as the IV argument).
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

import Control.Exception (bracket)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Cipher

-- | Supported symmetric cipher algorithms.
data CipherAlgorithm
  = AES128CBC | AES256CBC
  | AES128CTR | AES256CTR
  | AES128ECB | AES256ECB
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
        -> IO (Either BoringSSLError ByteString)
encrypt algo key iv plaintext
  | BS.length key /= cipherKeyLength algo =
      return (Left (BoringSSLError 0 ("encrypt: key length " ++ show (BS.length key) ++ " does not match expected " ++ show (cipherKeyLength algo))))
  | BS.length iv /= cipherIVLength algo =
      return (Left (BoringSSLError 0 ("encrypt: IV length " ++ show (BS.length iv) ++ " does not match expected " ++ show (cipherIVLength algo))))
  | otherwise =
      withByteString key $ \keyPtr _ ->
        withByteString plaintext $ \inPtr inLen -> do
        let ivAction f =
              if cipherIVLength algo == 0
                then f nullPtr
                else withByteString iv $ \ivPtr _ -> f ivPtr
        ivAction $ \ivPtr ->
          bracket c_EVP_CIPHER_CTX_new
                  (\ctx -> when (ctx /= nullPtr) (c_EVP_CIPHER_CTX_free ctx))
                  $ \ctx ->
            if ctx == nullPtr
              then return (Left (BoringSSLError 0 "encrypt: EVP_CIPHER_CTX_new failed"))
              else do
                let maxOutLen = fromIntegral inLen + (16 :: Int)
                fptr <- BSI.mallocByteString maxOutLen
                result <- withForeignPtr fptr $ \outPtr -> do
                  rc1 <- c_EVP_EncryptInit_ex ctx (cipherPtr algo) nullPtr keyPtr ivPtr
                  if rc1 /= 1
                    then do
                      merr <- getBoringSSLError
                      return (Left (maybe (BoringSSLError 0 "encrypt: EncryptInit failed") id merr))
                    else do
                      alloca $ \updateLenPtr ->
                        alloca $ \finalLenPtr -> do
                          rc2 <- c_EVP_EncryptUpdate_ex ctx (castPtr outPtr) updateLenPtr
                                   (fromIntegral maxOutLen) inPtr inLen
                          if rc2 /= 1
                            then do
                              merr <- getBoringSSLError
                              return (Left (maybe (BoringSSLError 0 "encrypt: EncryptUpdate failed") id merr))
                            else do
                              updateLen <- peek updateLenPtr
                              let remaining = fromIntegral maxOutLen - updateLen
                              rc3 <- c_EVP_EncryptFinal_ex2 ctx
                                       (castPtr outPtr `plusPtr` fromIntegral updateLen)
                                       finalLenPtr remaining
                              if rc3 /= 1
                                then do
                                  merr <- getBoringSSLError
                                  return (Left (maybe (BoringSSLError 0 "encrypt: EncryptFinal failed") id merr))
                                else do
                                  finalLen <- peek finalLenPtr
                                  return (Right (fromIntegral (updateLen + finalLen)))
                case result of
                  Left err  -> return (Left err)
                  Right len -> return (Right (BSI.BS fptr len))

-- | Decrypt ciphertext. CBC and ECB modes remove PKCS#7 padding automatically.
-- For ECB mode, pass an empty IV (@BS.empty@).
-- Returns Left on failure (e.g. bad padding).
decrypt :: CipherAlgorithm -> ByteString -> ByteString -> ByteString
        -> IO (Either BoringSSLError ByteString)
decrypt algo key iv ciphertext
  | BS.length key /= cipherKeyLength algo =
      return (Left (BoringSSLError 0 ("decrypt: key length " ++ show (BS.length key) ++ " does not match expected " ++ show (cipherKeyLength algo))))
  | BS.length iv /= cipherIVLength algo =
      return (Left (BoringSSLError 0 ("decrypt: IV length " ++ show (BS.length iv) ++ " does not match expected " ++ show (cipherIVLength algo))))
  | otherwise =
      withByteString key $ \keyPtr _ ->
        withByteString ciphertext $ \inPtr inLen -> do
        let ivAction f =
              if cipherIVLength algo == 0
                then f nullPtr
                else withByteString iv $ \ivPtr _ -> f ivPtr
        ivAction $ \ivPtr ->
          bracket c_EVP_CIPHER_CTX_new
                  (\ctx -> when (ctx /= nullPtr) (c_EVP_CIPHER_CTX_free ctx))
                  $ \ctx ->
            if ctx == nullPtr
              then return (Left (BoringSSLError 0 "decrypt: EVP_CIPHER_CTX_new failed"))
              else do
                let maxOutLen = fromIntegral inLen + (16 :: Int)
                fptr <- BSI.mallocByteString maxOutLen
                result <- withForeignPtr fptr $ \outPtr -> do
                  rc1 <- c_EVP_DecryptInit_ex ctx (cipherPtr algo) nullPtr keyPtr ivPtr
                  if rc1 /= 1
                    then do
                      merr <- getBoringSSLError
                      return (Left (maybe (BoringSSLError 0 "decrypt: DecryptInit failed") id merr))
                    else do
                      alloca $ \updateLenPtr ->
                        alloca $ \finalLenPtr -> do
                          rc2 <- c_EVP_DecryptUpdate_ex ctx (castPtr outPtr) updateLenPtr
                                   (fromIntegral maxOutLen) inPtr inLen
                          if rc2 /= 1
                            then do
                              merr <- getBoringSSLError
                              return (Left (maybe (BoringSSLError 0 "decrypt: DecryptUpdate failed") id merr))
                            else do
                              updateLen <- peek updateLenPtr
                              let remaining = fromIntegral maxOutLen - updateLen
                              rc3 <- c_EVP_DecryptFinal_ex2 ctx
                                       (castPtr outPtr `plusPtr` fromIntegral updateLen)
                                       finalLenPtr remaining
                              if rc3 /= 1
                                then do
                                  merr <- getBoringSSLError
                                  return (Left (maybe (BoringSSLError 0 "decrypt: bad padding or corrupted ciphertext") id merr))
                                else do
                                  finalLen <- peek finalLenPtr
                                  return (Right (fromIntegral (updateLen + finalLen)))
                case result of
                  Left err  -> return (Left err)
                  Right len -> return (Right (BSI.BS fptr len))
