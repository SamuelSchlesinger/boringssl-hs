-- | HMAC message authentication codes (RFC 2104).
--
-- Use HMAC to authenticate messages with a shared secret key. Keys may
-- be any length (longer keys are hashed down internally per the HMAC
-- construction); prefer keys of at least the digest size.
--
-- Verify received MACs with 'hmacVerify' — never with @(==)@ — so the
-- comparison runs in constant time.
--
-- This module is not for password storage: use "Crypto.BoringSSL.PBKDF2"
-- or "Crypto.BoringSSL.Scrypt" for passwords.
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

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
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
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.HMAC

-- | Compute HMAC in one shot. Pure, deterministic, and total: every key
-- and message is valid input.
--
-- @hmac algo key message@ computes the HMAC of @message@ under @key@
-- with the specified hash algorithm. The result has 'ID.digestSize'
-- @algo@ bytes.
hmac :: Algorithm -> ByteString -> ByteString -> ByteString
hmac algo key msg = unsafePerformIO $
  withByteString key $ \keyPtr keyLen ->
    withByteString msg $ \msgPtr msgLen -> do
      let md = ID.evpMD algo
          outSize = ID.digestSize algo
      fptr <- BSI.mallocByteString outSize
      result <- withForeignPtr fptr $ \outPtr ->
        alloca $ \outLenPtr -> do
          ret <- c_HMAC md keyPtr keyLen msgPtr msgLen (castPtr outPtr) outLenPtr
          if ret == nullPtr
            then return Nothing
            else Just . fromIntegral <$> peek outLenPtr
      case result of
        -- HMAC over a one-shot buffer cannot fail for any input; NULL
        -- would mean allocation failure inside BoringSSL.
        Nothing -> errorWithoutStackTrace "Crypto.BoringSSL.HMAC.hmac: HMAC returned NULL (allocation failure)"
        Just actualLen -> return (BSI.BS fptr actualLen)
{-# NOINLINE hmac #-}

-- | An incremental HMAC context. Automatically freed by GC. Concurrent
-- use from multiple threads is safe but serialized by an internal lock.
data HMACCtx = HMACCtx !(MVar ()) !(ForeignPtr HMAC_CTX)

-- | Initialize a streaming HMAC context.
hmacInit :: Algorithm -> ByteString -> IO (Either CryptoError HMACCtx)
hmacInit algo key = mask_ $ do
  ctx <- c_HMAC_CTX_new
  if ctx == nullPtr
    then return (Left (AllocationFailure "hmacInit: HMAC_CTX_new returned NULL"))
    else do
      withByteString key $ \keyPtr keyLen -> do
        rc <- c_HMAC_Init_ex ctx keyPtr keyLen (ID.evpMD algo) nullPtr
        if rc /= 1
          then do
            c_HMAC_CTX_free ctx
            return (Left (OperationFailed "hmacInit: HMAC_Init_ex failed"))
          else do
            fptr <- newForeignPtr c_HMAC_CTX_free_funptr ctx
            lock <- newMVar ()
            return (Right (HMACCtx lock fptr))

-- | Feed more data into the HMAC context.
hmacUpdate :: HMACCtx -> ByteString -> IO (Either CryptoError ())
hmacUpdate (HMACCtx lock fptr) bs = withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx ->
    withByteString bs $ \dataPtr dataLen -> do
      rc <- c_HMAC_Update ctx dataPtr dataLen
      if rc /= 1
        then return (Left (OperationFailed "hmacUpdate: HMAC_Update failed"))
        else return (Right ())

-- | Finalize the HMAC and return the MAC value.
hmacFinalize :: HMACCtx -> IO (Either CryptoError ByteString)
hmacFinalize (HMACCtx lock fptr) = withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> do
    fout <- BSI.mallocByteString ID.evpMaxMdSize
    result <- withForeignPtr fout $ \outPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_HMAC_Final ctx (castPtr outPtr) outLenPtr
        if rc /= 1
          then return Nothing
          else Just . fromIntegral <$> peek outLenPtr
    case result of
      Nothing -> return (Left (OperationFailed "hmacFinalize: HMAC_Final failed"))
      Just actualLen -> return (Right (BSI.BS fout actualLen))

-- | Verify an HMAC in constant time, fail-closed.
--
-- @hmacVerify algo key message expected@ recomputes the MAC and compares
-- it with @expected@ using constant-time comparison. Returns 'False' for
-- any mismatch, including an @expected@ value of the wrong length.
hmacVerify :: Algorithm -> ByteString -> ByteString -> ByteString -> Bool
hmacVerify algo key msg expected = constTimeEq (hmac algo key msg) expected
