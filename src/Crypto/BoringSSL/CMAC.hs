-- | AES-CMAC message authentication codes.
--
-- Provides one-shot AES-CMAC computation and an incremental streaming API.
-- CMAC is a MAC based on AES-CBC defined in RFC 4493.
module Crypto.BoringSSL.CMAC
  ( -- * One-shot
    cmac
    -- * Incremental
  , CMACCtx
  , cmacInit
  , cmacUpdate
  , cmacFinalize
    -- * Error type
  , BoringSSLError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.CMAC
import Crypto.BoringSSL.Internal.FFI.Cipher (c_EVP_aes_128_cbc, c_EVP_aes_256_cbc)

-- | CMAC tag size in bytes.
cmacTagSize :: Int
cmacTagSize = 16

-- | Select the appropriate AES-CBC cipher for the given key length.
cipherForKeyLen :: Int -> Ptr a
cipherForKeyLen 16 = castPtr c_EVP_aes_128_cbc
cipherForKeyLen 32 = castPtr c_EVP_aes_256_cbc
cipherForKeyLen _  = error "cmac: key must be 16 or 32 bytes"

-- | Compute AES-CMAC in one shot (pure, deterministic).
--
-- @cmac key message@ computes the AES-CMAC of @message@ using @key@.
-- The key must be 16 bytes (AES-128) or 32 bytes (AES-256).
-- Returns a 16-byte authentication tag.
cmac :: ByteString -> ByteString -> ByteString
cmac key msg
  | BS.length key /= 16 && BS.length key /= 32 =
      error "cmac: key must be 16 or 32 bytes"
  | otherwise = unsafePerformIO $
      withByteString key $ \keyPtr keyLen ->
        withByteString msg $ \msgPtr msgLen -> do
          fptr <- BSI.mallocByteString cmacTagSize
          withForeignPtr fptr $ \outPtr -> do
            rc <- c_AES_CMAC (castPtr outPtr) keyPtr keyLen msgPtr msgLen
            if rc /= 1
              then fail "cmac: AES_CMAC failed"
              else return (BSI.BS fptr cmacTagSize)
{-# NOINLINE cmac #-}

-- | An incremental CMAC context.
newtype CMACCtx = CMACCtx (ForeignPtr CMAC_CTX)

-- | Initialize a streaming CMAC context.
--
-- The key must be 16 bytes (AES-128) or 32 bytes (AES-256).
-- Selects the appropriate AES-CBC cipher automatically.
cmacInit :: ByteString -> IO (Either BoringSSLError CMACCtx)
cmacInit key
  | BS.length key /= 16 && BS.length key /= 32 =
      return (Left (BoringSSLError 0 "cmacInit: key must be 16 or 32 bytes"))
  | otherwise = mask_ $ do
      ctx <- c_CMAC_CTX_new
      if ctx == nullPtr
        then return (Left (BoringSSLError 0 "cmacInit: CMAC_CTX_new returned NULL"))
        else do
          let cipher = cipherForKeyLen (BS.length key)
          withByteString key $ \keyPtr keyLen -> do
            rc <- c_CMAC_Init ctx keyPtr keyLen cipher nullPtr
            if rc /= 1
              then do
                c_CMAC_CTX_free ctx
                return (Left (BoringSSLError 0 "cmacInit: CMAC_Init failed"))
              else do
                fptr <- newForeignPtr c_CMAC_CTX_free_funptr ctx
                return (Right (CMACCtx fptr))

-- | Feed more data into the CMAC context.
cmacUpdate :: CMACCtx -> ByteString -> IO (Either BoringSSLError ())
cmacUpdate (CMACCtx fptr) bs =
  withForeignPtr fptr $ \ctx ->
    withByteString bs $ \dataPtr dataLen -> do
      rc <- c_CMAC_Update ctx dataPtr dataLen
      if rc /= 1
        then return (Left (BoringSSLError 0 "cmacUpdate: CMAC_Update failed"))
        else return (Right ())

-- | Finalize the CMAC and return the 16-byte authentication tag.
cmacFinalize :: CMACCtx -> IO (Either BoringSSLError ByteString)
cmacFinalize (CMACCtx fptr) =
  withForeignPtr fptr $ \ctx -> do
    fout <- BSI.mallocByteString cmacTagSize
    withForeignPtr fout $ \outPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_CMAC_Final ctx (castPtr outPtr) outLenPtr
        if rc /= 1
          then return (Left (BoringSSLError 0 "cmacFinalize: CMAC_Final failed"))
          else do
            actualLen <- fromIntegral <$> peek outLenPtr
            return (Right (BSI.BS fout actualLen))
