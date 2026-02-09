-- | Cryptographic hash functions.
--
-- Supports SHA-1, SHA-2 (224\/256\/384\/512\/512-256), MD5, and BLAKE2b-256.
-- Both one-shot hashing and incremental streaming APIs are provided.
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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
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
newtype DigestCtx = DigestCtx (ForeignPtr EVP_MD_CTX)

-- | Initialize a streaming digest context for the given algorithm.
digestInit :: Algorithm -> IO DigestCtx
digestInit algo = mask_ $ do
  ctx <- c_EVP_MD_CTX_new
  if ctx == nullPtr
    then fail "digestInit: EVP_MD_CTX_new returned NULL"
    else do
      rc <- c_EVP_DigestInit_ex ctx (ID.evpMD algo) nullPtr
      if rc /= 1
        then do
          c_EVP_MD_CTX_free ctx
          fail "digestInit: EVP_DigestInit_ex failed"
        else do
          fptr <- newForeignPtr c_EVP_MD_CTX_free_funptr ctx
          return (DigestCtx fptr)

-- | Feed more data into the digest context.
digestUpdate :: DigestCtx -> ByteString -> IO ()
digestUpdate (DigestCtx fptr) bs =
  withForeignPtr fptr $ \ctx ->
    withByteString bs $ \dataPtr dataLen -> do
      rc <- c_EVP_DigestUpdate ctx dataPtr dataLen
      if rc /= 1
        then fail "digestUpdate: EVP_DigestUpdate failed"
        else return ()

-- | Finalize the digest and return the hash. The context should not be
-- used after this call.
digestFinalize :: DigestCtx -> IO ByteString
digestFinalize (DigestCtx fptr) =
  withForeignPtr fptr $ \ctx -> do
    -- EVP_MAX_MD_SIZE is 64 (for SHA-512)
    fout <- BSI.mallocByteString 64
    actualLen <- withForeignPtr fout $ \outPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_EVP_DigestFinal_ex ctx (castPtr outPtr) outLenPtr
        if rc /= 1
          then fail "digestFinalize: EVP_DigestFinal_ex failed"
          else fromIntegral <$> peek outLenPtr
    return (BSI.BS fout actualLen)
