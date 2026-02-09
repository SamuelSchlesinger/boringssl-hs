-- | HMAC message authentication codes.
--
-- Provides one-shot HMAC computation, an incremental streaming API,
-- and constant-time verification to prevent timing attacks.
module Crypto.BoringSSL.HMAC
  ( -- * One-shot
    hmac
    -- * Streaming
  , HMACCtx
  , hmacInit
  , hmacUpdate
  , hmacFinalize
    -- * Verification
  , hmacVerify
  , constTimeEq
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString, constTimeEq)
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.FFI.HMAC

-- | Compute HMAC in one shot (pure, deterministic).
--
-- @hmac algo key message@ computes the HMAC of @message@ using @key@
-- with the specified hash algorithm.
hmac :: Algorithm -> ByteString -> ByteString -> ByteString
hmac algo key msg = unsafePerformIO $
  withByteString key $ \keyPtr keyLen ->
    withByteString msg $ \msgPtr msgLen -> do
      let md = ID.evpMD algo
          outSize = ID.digestSize algo
      fptr <- BSI.mallocByteString outSize
      actualLen <- withForeignPtr fptr $ \outPtr ->
        alloca $ \outLenPtr -> do
          ret <- c_HMAC md keyPtr keyLen msgPtr msgLen (castPtr outPtr) outLenPtr
          if ret == nullPtr
            then error "hmac: HMAC returned NULL (should never happen)"
            else fromIntegral <$> peek outLenPtr
      return (BSI.BS fptr actualLen)
{-# NOINLINE hmac #-}

-- | An incremental HMAC context.
newtype HMACCtx = HMACCtx (ForeignPtr HMAC_CTX)

-- | Initialize a streaming HMAC context.
hmacInit :: Algorithm -> ByteString -> IO HMACCtx
hmacInit algo key = mask_ $ do
  ctx <- c_HMAC_CTX_new
  if ctx == nullPtr
    then fail "hmacInit: HMAC_CTX_new returned NULL"
    else do
      withByteString key $ \keyPtr keyLen -> do
        rc <- c_HMAC_Init_ex ctx keyPtr keyLen (ID.evpMD algo) nullPtr
        if rc /= 1
          then do
            c_HMAC_CTX_free ctx
            fail "hmacInit: HMAC_Init_ex failed"
          else do
            fptr <- newForeignPtr c_HMAC_CTX_free_funptr ctx
            return (HMACCtx fptr)

-- | Feed more data into the HMAC context.
hmacUpdate :: HMACCtx -> ByteString -> IO ()
hmacUpdate (HMACCtx fptr) bs =
  withForeignPtr fptr $ \ctx ->
    withByteString bs $ \dataPtr dataLen -> do
      rc <- c_HMAC_Update ctx dataPtr dataLen
      if rc /= 1
        then fail "hmacUpdate: HMAC_Update failed"
        else return ()

-- | Finalize the HMAC and return the MAC value.
hmacFinalize :: HMACCtx -> IO ByteString
hmacFinalize (HMACCtx fptr) =
  withForeignPtr fptr $ \ctx -> do
    -- EVP_MAX_MD_SIZE is 64
    fout <- BSI.mallocByteString 64
    actualLen <- withForeignPtr fout $ \outPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_HMAC_Final ctx (castPtr outPtr) outLenPtr
        if rc /= 1
          then fail "hmacFinalize: HMAC_Final failed"
          else fromIntegral <$> peek outLenPtr
    return (BSI.BS fout actualLen)

-- | Verify an HMAC in constant time.
-- Computes HMAC of @message@ using @key@ and compares with @expected@
-- using constant-time comparison to prevent timing attacks.
hmacVerify :: Algorithm -> ByteString -> ByteString -> ByteString -> Bool
hmacVerify algo key msg expected = constTimeEq (hmac algo key msg) expected
