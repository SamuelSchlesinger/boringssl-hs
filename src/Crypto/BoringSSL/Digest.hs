-- | Cryptographic hash functions.
--
-- Supports SHA-1, SHA-2 (224\/256\/384\/512\/512-256), MD5, and BLAKE2b-256.
-- Both one-shot hashing and incremental streaming APIs are provided.
--
-- __Algorithm security status:__
--
-- * __SHA-256, SHA-384, SHA-512, SHA-512\/256, SHA-224, BLAKE2b-256__ — safe
--   for all uses including digital signatures and integrity.
-- * __SHA-1__ — deprecated for digital signatures and certificate validation
--   (NIST, since 2011). Acceptable for HMAC and non-collision-resistant uses.
-- * __MD5__ — cryptographically broken. Provided only for legacy
--   interoperability (e.g. existing protocol checksums). Do not use for
--   signatures, integrity, or new designs.
module Crypto.BoringSSL.Digest
  ( -- * Algorithms
    Algorithm(..)
  , digestSize
    -- * One-shot hashing
  , hash
  , hashSHA256
  , hashSHA512
  , hashSHA1
  , hashSHA224
  , hashSHA384
  , hashSHA512_256
  , hashMD5
  , hashBLAKE2b256
    -- * Streaming
  , DigestCtx
  , digestInit
  , digestUpdate
  , digestFinalize
  , digestCopy
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Control.Concurrent.MVar
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Digest
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID

-- | Hash a ByteString using the specified algorithm.
hash :: Algorithm -> ByteString -> ByteString
hash SHA256     = hashSHA256
hash SHA512     = hashSHA512
hash SHA1       = hashSHA1
hash SHA224     = hashSHA224
hash SHA384     = hashSHA384
hash SHA512_256 = hashSHA512_256
hash MD5        = hashMD5
hash BLAKE2b256 = hashBLAKE2b256

-- | Compute the SHA-256 hash of a ByteString (32 bytes).
hashSHA256 :: ByteString -> ByteString
hashSHA256 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 32 $ \outPtr ->
      c_SHA256 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA256 #-}

-- | Compute the SHA-512 hash of a ByteString (64 bytes).
hashSHA512 :: ByteString -> ByteString
hashSHA512 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 64 $ \outPtr ->
      c_SHA512 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA512 #-}

-- | Compute the SHA-1 hash of a ByteString (20 bytes).
--
-- __WARNING:__ SHA-1 is deprecated for digital signatures and certificate
-- validation. It remains acceptable for HMAC and non-collision-resistant
-- applications. For new designs, prefer 'hashSHA256' or stronger.
hashSHA1 :: ByteString -> ByteString
hashSHA1 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 20 $ \outPtr ->
      c_SHA1 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA1 #-}

-- | Compute the SHA-224 hash of a ByteString (28 bytes).
hashSHA224 :: ByteString -> ByteString
hashSHA224 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 28 $ \outPtr ->
      c_SHA224 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA224 #-}

-- | Compute the SHA-384 hash of a ByteString (48 bytes).
hashSHA384 :: ByteString -> ByteString
hashSHA384 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 48 $ \outPtr ->
      c_SHA384 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA384 #-}

-- | Compute the SHA-512/256 hash of a ByteString (32 bytes).
hashSHA512_256 :: ByteString -> ByteString
hashSHA512_256 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 32 $ \outPtr ->
      c_SHA512_256 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashSHA512_256 #-}

-- | Compute the MD5 hash of a ByteString (16 bytes).
--
-- __WARNING:__ MD5 is cryptographically broken — practical collision attacks
-- exist. Provided only for legacy interoperability (e.g. existing protocol
-- checksums) and HMAC. Do not use for digital signatures or integrity in new
-- designs.
hashMD5 :: ByteString -> ByteString
hashMD5 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 16 $ \outPtr ->
      c_MD5 dataPtr dataLen outPtr >> return ()
{-# NOINLINE hashMD5 #-}

-- | Compute the BLAKE2b-256 hash of a ByteString (32 bytes).
hashBLAKE2b256 :: ByteString -> ByteString
hashBLAKE2b256 bs = unsafePerformIO $
  withByteString bs $ \dataPtr dataLen ->
    createByteString 32 $ \outPtr ->
      c_BLAKE2B256 dataPtr dataLen outPtr
{-# NOINLINE hashBLAKE2b256 #-}

-- | Output size in bytes for each algorithm.
digestSize :: Algorithm -> Int
digestSize = ID.digestSize

-- Streaming digest

-- | An incremental digest context.
-- Thread-safe: concurrent operations are serialized via an internal 'MVar'.
-- Once finalized, further operations will fail.
data DigestCtx = DigestCtx !(MVar (Maybe (ForeignPtr EVP_MD_CTX)))

-- | Initialize a streaming digest context for the given algorithm.
digestInit :: Algorithm -> IO (Either CryptoError DigestCtx)
digestInit algo = mask_ $ do
  ctx <- c_EVP_MD_CTX_new
  if ctx == nullPtr
    then return (Left (AllocationFailure "digestInit: EVP_MD_CTX_new returned NULL"))
    else do
      rc <- c_EVP_DigestInit_ex ctx (ID.evpMD algo) nullPtr
      if rc /= 1
        then do
          c_EVP_MD_CTX_free ctx
          return (Left (OperationFailed "digestInit: EVP_DigestInit_ex failed"))
        else do
          fptr <- newForeignPtr c_EVP_MD_CTX_free_funptr ctx
          mv <- newMVar (Just fptr)
          return (Right (DigestCtx mv))

-- | Feed more data into the digest context.
digestUpdate :: DigestCtx -> ByteString -> IO (Either CryptoError ())
digestUpdate (DigestCtx mv) bs =
  withMVar mv $ \mfptr -> case mfptr of
    Nothing -> return (Left (OperationFailed "digestUpdate: context already finalized"))
    Just fptr -> withForeignPtr fptr $ \ctx ->
      withByteString bs $ \dataPtr dataLen -> do
        rc <- c_EVP_DigestUpdate ctx dataPtr dataLen
        if rc /= 1
          then return (Left (OperationFailed "digestUpdate: EVP_DigestUpdate failed"))
          else return (Right ())

-- | Create a copy of a digest context. The copy is independent:
-- updating or finalizing one does not affect the other.
digestCopy :: DigestCtx -> IO (Either CryptoError DigestCtx)
digestCopy (DigestCtx mv) =
  withMVar mv $ \mfptr -> case mfptr of
    Nothing -> return (Left (OperationFailed "digestCopy: context already finalized"))
    Just srcFPtr -> mask_ $
      withForeignPtr srcFPtr $ \srcCtx -> do
        dstCtx <- c_EVP_MD_CTX_new
        if dstCtx == nullPtr
          then return (Left (AllocationFailure "digestCopy: EVP_MD_CTX_new returned NULL"))
          else do
            rc <- c_EVP_MD_CTX_copy_ex dstCtx srcCtx
            if rc /= 1
              then do
                c_EVP_MD_CTX_free dstCtx
                return (Left (OperationFailed "digestCopy: EVP_MD_CTX_copy_ex failed"))
              else do
                dstFPtr <- newForeignPtr c_EVP_MD_CTX_free_funptr dstCtx
                dstMv <- newMVar (Just dstFPtr)
                return (Right (DigestCtx dstMv))

-- | Finalize the digest and return the hash. Marks the context as
-- finalized; any subsequent operation on this context will fail.
digestFinalize :: DigestCtx -> IO (Either CryptoError ByteString)
digestFinalize (DigestCtx mv) =
  modifyMVar mv $ \mfptr -> case mfptr of
    Nothing -> return (Nothing, Left (OperationFailed "digestFinalize: context already finalized"))
    Just fptr -> do
      result <- withForeignPtr fptr $ \ctx -> do
        -- EVP_MAX_MD_SIZE is 64 (for SHA-512)
        fout <- BSI.mallocByteString 64
        withForeignPtr fout $ \outPtr ->
          alloca $ \outLenPtr -> do
            rc <- c_EVP_DigestFinal_ex ctx (castPtr outPtr) outLenPtr
            if rc /= 1
              then return (Left (OperationFailed "digestFinalize: EVP_DigestFinal_ex failed"))
              else do
                actualLen <- fromIntegral <$> peek outLenPtr
                return (Right (BSI.BS fout actualLen))
      return (Nothing, result)
