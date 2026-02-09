module Crypto.BoringSSL.Base64
  ( encode
  , decode
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.Base64

-- | Base64-encode a ByteString (pure, deterministic).
encode :: ByteString -> ByteString
encode bs = unsafePerformIO $
  withByteString bs $ \srcPtr srcLen -> do
    alloca $ \outLenPtr -> do
      _ <- c_EVP_EncodedLength outLenPtr srcLen
      maxLen <- peek outLenPtr
      -- EVP_EncodeBlock returns the number of bytes written (not including NUL)
      fptr <- BSI.mallocByteString (fromIntegral maxLen)
      actualLen <- withForeignPtr fptr $ \dstPtr ->
        c_EVP_EncodeBlock (castPtr dstPtr) srcPtr srcLen
      return (BSI.BS fptr (fromIntegral actualLen))
{-# NOINLINE encode #-}

-- | Base64-decode a ByteString (pure, deterministic).
-- Returns Left with an error message on invalid input.
decode :: ByteString -> Either String ByteString
decode bs = unsafePerformIO $
  withByteString bs $ \inPtr inLen -> do
    alloca $ \maxOutLenPtr -> do
      rc1 <- c_EVP_DecodedLength maxOutLenPtr inLen
      if rc1 /= 1
        then return (Left "Base64.decode: invalid input length")
        else do
          maxOutLen <- peek maxOutLenPtr
          fptr <- BSI.mallocByteString (fromIntegral maxOutLen)
          result <- withForeignPtr fptr $ \outPtr ->
            alloca $ \outLenPtr -> do
              rc2 <- c_EVP_DecodeBase64 (castPtr outPtr) outLenPtr maxOutLen inPtr inLen
              if rc2 /= 1
                then return (Left "Base64.decode: invalid base64 input")
                else do
                  actualLen <- peek outLenPtr
                  return (Right (fromIntegral actualLen))
          case result of
            Left err   -> return (Left err)
            Right len  -> return (Right (BSI.BS fptr len))
{-# NOINLINE decode #-}
