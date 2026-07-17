-- | HKDF key derivation (RFC 5869).
--
-- Provides the full extract-then-expand operation in one call ('hkdf'),
-- or the individual 'hkdfExtract' and 'hkdfExpand' steps. The
-- intermediate pseudorandom key flows between them as an opaque 'PRK'
-- backed by secure memory, so chaining extract and expand never moves
-- the secret through an ordinary 'ByteString'.
--
-- The @salt@ may be empty (RFC 5869 then uses a zeroed salt), but a
-- random salt strengthens the extraction and is recommended when you
-- can transmit one.
--
-- __Not for passwords__: HKDF assumes high-entropy input keying
-- material. To derive keys from a password, use
-- "Crypto.BoringSSL.PBKDF2" or "Crypto.BoringSSL.Scrypt".
module Crypto.BoringSSL.HKDF
  ( -- * One-shot
    hkdf
    -- * Extract and expand
  , PRK
  , hkdfExtract
  , hkdfExpand
  , prkFromBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as BSU
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

-- | A pseudorandom key produced by 'hkdfExtract' (or imported with
-- 'prkFromBytes'), held in secure memory. 'Eq' is constant-time and
-- 'Show' reveals only the length.
newtype PRK = PRK SecureBytes
  deriving (Eq, Show)

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
-- @hkdfExtract hashAlgo secret salt@ returns the 'PRK' (of the digest's
-- size), ready to pass to 'hkdfExpand'.
hkdfExtract :: Algorithm -> ByteString -> ByteString -> Either CryptoError PRK
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
          | actualLen == maxLen -> return (Right (PRK sb))
          | otherwise -> do
              -- Trim to actual length (should always equal maxLen in practice)
              trimmed <- createSecureBytes actualLen $ \dstPtr ->
                withSecureBytes sb $ \srcPtr _ ->
                  copyBytes (castPtr dstPtr) (castPtr srcPtr) actualLen
              return (Right (PRK trimmed))
{-# NOINLINE hkdfExtract #-}

-- | HKDF-Expand: expand a 'PRK' into output keying material.
--
-- @hkdfExpand hashAlgo prk info outputLength@
hkdfExpand :: Algorithm -> PRK -> ByteString -> Int -> Either CryptoError SecureBytes
hkdfExpand algo (PRK prkSB) info outLen
  | outLen <= 0 = Left (InvalidInput "hkdfExpand: output length must be positive")
  | outLen > 255 * ID.digestSize algo = Left (InvalidInput "hkdfExpand: output length exceeds RFC 5869 maximum (255 * hash length)")
  | otherwise = unsafePerformIO $
  withSecureBytes prkSB $ \prkPtr prkLen ->
    withByteString info $ \infoPtr infoLen -> do
      sb <- createSecureBytes outLen $ \_ -> return ()
      rc <- withSecureBytes sb $ \outPtr _ ->
        c_HKDF_expand (castPtr outPtr) (fromIntegral outLen) (ID.evpMD algo)
                prkPtr prkLen infoPtr infoLen
      if rc /= 1
        then return (Left (OperationFailed "hkdfExpand: HKDF_expand failed"))
        else return (Right sb)
{-# NOINLINE hkdfExpand #-}

-- | Import an externally-derived PRK. The bytes are copied into secure
-- memory; the original 'ByteString' remains an unprotected copy that
-- you should let go of promptly.
prkFromBytes :: ByteString -> PRK
prkFromBytes bs = unsafePerformIO $
  BSU.unsafeUseAsCStringLen bs $ \(srcPtr, len) ->
    PRK <$> createSecureBytes len (\dstPtr ->
      copyBytes (castPtr dstPtr) srcPtr len)
{-# NOINLINE prkFromBytes #-}
