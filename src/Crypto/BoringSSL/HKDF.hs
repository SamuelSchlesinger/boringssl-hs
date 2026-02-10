-- | HKDF key derivation (RFC 5869).
--
-- Provides the full extract-then-expand operation in one call ('hkdf'),
-- or the individual 'hkdfExtract' and 'hkdfExpand' steps.
module Crypto.BoringSSL.HKDF
  ( -- * One-shot
    hkdf
    -- * Extract and expand
  , hkdfExtract
  , hkdfExpand
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.HKDF
import Crypto.BoringSSL.Internal.SecureBytes

-- | Full HKDF (extract-then-expand) in one call (pure, deterministic).
--
-- @hkdf hashAlgo secret salt info outputLength@
hkdf :: Algorithm -> ByteString -> ByteString -> ByteString -> Int -> Either CryptoError SecureBytes
hkdf algo secret salt info outLen
  | outLen <= 0 = Left (InvalidInput "hkdf: output length must be positive")
  | outLen > 255 * ID.digestSize algo = Left (InvalidInput "hkdf: output length exceeds RFC 5869 maximum (255 * hash length)")
  | otherwise = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString salt $ \saltPtr saltLen ->
      withByteString info $ \infoPtr infoLen -> do
        sb <- createSecureBytes outLen $ \_ -> return ()
        rc <- withSecureBytes sb $ \outPtr _ ->
          c_HKDF (castPtr outPtr) (fromIntegral outLen) (ID.evpMD algo)
                  secretPtr secretLen saltPtr saltLen infoPtr infoLen
        if rc /= 1
          then return (Left (OperationFailed "hkdf: HKDF failed"))
          else return (Right sb)
{-# NOINLINE hkdf #-}

-- | HKDF-Extract: extract a pseudorandom key from input keying material.
--
-- @hkdfExtract hashAlgo secret salt@ returns the PRK.
hkdfExtract :: Algorithm -> ByteString -> ByteString -> Either CryptoError SecureBytes
hkdfExtract algo secret salt = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString salt $ \saltPtr saltLen -> do
      -- PRK size is the digest size
      let maxLen = ID.digestSize algo
      sb <- createSecureBytes maxLen $ \_ -> return ()
      result <- withSecureBytes sb $ \outPtr _ ->
        alloca $ \outLenPtr -> do
          rc <- c_HKDF_extract (castPtr outPtr) outLenPtr (ID.evpMD algo)
                  secretPtr secretLen saltPtr saltLen
          if rc /= 1
            then return Nothing
            else Just . fromIntegral <$> peek outLenPtr
      case result of
        Nothing -> return (Left (OperationFailed "hkdfExtract: HKDF_extract failed"))
        Just actualLen
          | actualLen == maxLen -> return (Right sb)
          | otherwise -> do
              -- Trim to actual length (should always equal maxLen in practice)
              trimmed <- createSecureBytes actualLen $ \dstPtr ->
                withSecureBytes sb $ \srcPtr _ ->
                  Foreign.Marshal.Utils.copyBytes (castPtr dstPtr) (castPtr srcPtr) actualLen
              return (Right trimmed)
{-# NOINLINE hkdfExtract #-}

-- | HKDF-Expand: expand a PRK into output keying material.
--
-- @hkdfExpand hashAlgo prk info outputLength@
hkdfExpand :: Algorithm -> ByteString -> ByteString -> Int -> Either CryptoError SecureBytes
hkdfExpand algo prk info outLen
  | outLen <= 0 = Left (InvalidInput "hkdfExpand: output length must be positive")
  | outLen > 255 * ID.digestSize algo = Left (InvalidInput "hkdfExpand: output length exceeds RFC 5869 maximum (255 * hash length)")
  | otherwise = unsafePerformIO $
  withByteString prk $ \prkPtr prkLen ->
    withByteString info $ \infoPtr infoLen -> do
      sb <- createSecureBytes outLen $ \_ -> return ()
      rc <- withSecureBytes sb $ \outPtr _ ->
        c_HKDF_expand (castPtr outPtr) (fromIntegral outLen) (ID.evpMD algo)
                prkPtr prkLen infoPtr infoLen
      if rc /= 1
        then return (Left (OperationFailed "hkdfExpand: HKDF_expand failed"))
        else return (Right sb)
{-# NOINLINE hkdfExpand #-}
