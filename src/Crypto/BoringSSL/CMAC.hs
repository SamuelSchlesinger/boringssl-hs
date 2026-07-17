-- | AES-CMAC message authentication codes (RFC 4493).
--
-- Provides one-shot AES-CMAC computation, an incremental streaming API,
-- and constant-time verification. Verify received tags with 'cmacVerify'
-- — never with @(==)@ — so the comparison runs in constant time.
--
-- Prefer "Crypto.BoringSSL.HMAC" unless you specifically need CMAC for
-- interoperability; and use "Crypto.BoringSSL.PBKDF2" or
-- "Crypto.BoringSSL.Scrypt" for passwords, never a MAC.
module Crypto.BoringSSL.CMAC
  ( -- * One-shot
    cmac
  , cmacTagSize
    -- * Incremental
  , CMACCtx
  , cmacInit
  , cmacUpdate
  , cmacFinalize
    -- * Verification
  , cmacVerify
  , constTimeEq
  ) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString, constTimeEq)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.CMAC
import Crypto.BoringSSL.Internal.FFI.Cipher (c_EVP_aes_128_cbc, c_EVP_aes_256_cbc)

-- | Size of a CMAC authentication tag in bytes (always 16, one AES block).
cmacTagSize :: Int
cmacTagSize = 16

-- | Verify an AES-CMAC tag in constant time, fail-closed.
--
-- @cmacVerify key message expected@ recomputes the tag and compares it
-- with @expected@ using constant-time comparison. Returns 'False' on any
-- mismatch — including an invalid key length or an @expected@ value that
-- is not 'cmacTagSize' bytes.
cmacVerify :: ByteString -> ByteString -> ByteString -> Bool
cmacVerify key msg expected =
  case cmac key msg of
    Left _    -> False
    Right tag -> constTimeEq tag expected

-- | Select the appropriate AES-CBC cipher for the given key length.
-- Returns Nothing for invalid key lengths.
cipherForKeyLen :: Int -> Maybe (Ptr a)
cipherForKeyLen 16 = Just (castPtr c_EVP_aes_128_cbc)
cipherForKeyLen 32 = Just (castPtr c_EVP_aes_256_cbc)
cipherForKeyLen _  = Nothing

-- | Compute AES-CMAC in one shot (pure, deterministic).
--
-- @cmac key message@ computes the AES-CMAC of @message@ using @key@.
-- The key must be 16 bytes (AES-128) or 32 bytes (AES-256).
-- Returns a 16-byte authentication tag, or 'Left' on invalid key length.
cmac :: ByteString -> ByteString -> Either CryptoError ByteString
cmac key msg
  | BS.length key /= 16 && BS.length key /= 32 =
      Left (InvalidInput "cmac: key must be 16 or 32 bytes")
  | otherwise = unsafePerformIO $
      withByteString key $ \keyPtr keyLen ->
        withByteString msg $ \msgPtr msgLen -> do
          fptr <- BSI.mallocByteString cmacTagSize
          withForeignPtr fptr $ \outPtr -> do
            rc <- c_AES_CMAC (castPtr outPtr) keyPtr keyLen msgPtr msgLen
            if rc /= 1
              then return (Left (OperationFailed "cmac: AES_CMAC failed"))
              else return (Right (BSI.BS fptr cmacTagSize))
{-# NOINLINE cmac #-}

-- | An incremental AES-CMAC context. Automatically freed by GC.
-- Concurrent use from multiple threads is safe but serialized by an
-- internal lock.
data CMACCtx = CMACCtx !(MVar ()) !(ForeignPtr CMAC_CTX)

-- | Initialize a streaming CMAC context.
--
-- The key must be 16 bytes (AES-128) or 32 bytes (AES-256).
-- Selects the appropriate AES-CBC cipher automatically.
cmacInit :: ByteString -> IO (Either CryptoError CMACCtx)
cmacInit key
  | BS.length key /= 16 && BS.length key /= 32 =
      return (Left (InvalidInput "cmacInit: key must be 16 or 32 bytes"))
  | otherwise = mask_ $ runExceptT $ do
      ctx <- liftIO c_CMAC_CTX_new
        >>= nonNull (AllocationFailure "cmacInit: CMAC_CTX_new returned NULL")
      let cipher = case cipherForKeyLen (BS.length key) of
            Just c  -> c
            Nothing -> error "cmacInit: unreachable (key length already checked)"
      rc <- liftIO $ withByteString key $ \keyPtr keyLen ->
        c_CMAC_Init ctx keyPtr keyLen cipher nullPtr
      if rc == 1
        then do
          fptr <- liftIO $ newForeignPtr c_CMAC_CTX_free_funptr ctx
          lock <- liftIO $ newMVar ()
          return (CMACCtx lock fptr)
        else do
          liftIO $ c_CMAC_CTX_free ctx
          throwE (OperationFailed "cmacInit: CMAC_Init failed")

-- | Feed more data into the CMAC context.
cmacUpdate :: CMACCtx -> ByteString -> IO (Either CryptoError ())
cmacUpdate (CMACCtx lock fptr) bs = withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx ->
    withByteString bs $ \dataPtr dataLen -> do
      rc <- c_CMAC_Update ctx dataPtr dataLen
      if rc /= 1
        then return (Left (OperationFailed "cmacUpdate: CMAC_Update failed"))
        else return (Right ())

-- | Finalize the CMAC and return the 16-byte authentication tag.
cmacFinalize :: CMACCtx -> IO (Either CryptoError ByteString)
cmacFinalize (CMACCtx lock fptr) = withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    fout <- liftIO $ BSI.mallocByteString cmacTagSize
    ExceptT $ withForeignPtr fout $ \outPtr -> runExceptT $
      allocaE $ \outLenPtr -> do
        rc <- liftIO $ c_CMAC_Final ctx (castPtr outPtr) outLenPtr
        checkRC (OperationFailed "cmacFinalize: CMAC_Final failed") rc
        actualLen <- liftIO $ fromIntegral <$> peek outLenPtr
        return (BSI.BS fout actualLen)
