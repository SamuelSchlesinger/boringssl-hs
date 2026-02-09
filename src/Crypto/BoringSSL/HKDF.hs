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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.FFI.HKDF

-- | Full HKDF (extract-then-expand) in one call (pure, deterministic).
--
-- @hkdf hashAlgo secret salt info outputLength@
hkdf :: Algorithm -> ByteString -> ByteString -> ByteString -> Int -> ByteString
hkdf algo secret salt info outLen = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString salt $ \saltPtr saltLen ->
      withByteString info $ \infoPtr infoLen ->
        createByteString outLen $ \outPtr -> do
          rc <- c_HKDF outPtr (fromIntegral outLen) (ID.evpMD algo)
                  secretPtr secretLen saltPtr saltLen infoPtr infoLen
          if rc /= 1
            then fail "hkdf: HKDF failed"
            else return ()
{-# NOINLINE hkdf #-}

-- | HKDF-Extract: extract a pseudorandom key from input keying material.
--
-- @hkdfExtract hashAlgo secret salt@ returns the PRK.
hkdfExtract :: Algorithm -> ByteString -> ByteString -> ByteString
hkdfExtract algo secret salt = unsafePerformIO $
  withByteString secret $ \secretPtr secretLen ->
    withByteString salt $ \saltPtr saltLen -> do
      -- PRK size is the digest size
      let maxLen = ID.digestSize algo
      fptr <- BSI.mallocByteString maxLen
      actualLen <- withForeignPtr fptr $ \outPtr ->
        alloca $ \outLenPtr -> do
          rc <- c_HKDF_extract (castPtr outPtr) outLenPtr (ID.evpMD algo)
                  secretPtr secretLen saltPtr saltLen
          if rc /= 1
            then fail "hkdfExtract: HKDF_extract failed"
            else fromIntegral <$> peek outLenPtr
      return (BSI.BS fptr actualLen)
{-# NOINLINE hkdfExtract #-}

-- | HKDF-Expand: expand a PRK into output keying material.
--
-- @hkdfExpand hashAlgo prk info outputLength@
hkdfExpand :: Algorithm -> ByteString -> ByteString -> Int -> ByteString
hkdfExpand algo prk info outLen = unsafePerformIO $
  withByteString prk $ \prkPtr prkLen ->
    withByteString info $ \infoPtr infoLen ->
      createByteString outLen $ \outPtr -> do
        rc <- c_HKDF_expand outPtr (fromIntegral outLen) (ID.evpMD algo)
                prkPtr prkLen infoPtr infoLen
        if rc /= 1
          then fail "hkdfExpand: HKDF_expand failed"
          else return ()
{-# NOINLINE hkdfExpand #-}
