module Crypto.BoringSSL.Internal.Buffer
  ( withByteString
  , createByteString
  , createByteStringLen
  , packOpenSSLBuffer
  , constTimeEq
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Control.Exception (finally)
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_free, c_CRYPTO_memcmp)
import System.IO.Unsafe (unsafePerformIO)

-- | Use a ByteString as a C pointer and length. For empty ByteStrings,
-- guarantees a non-null pointer (some C APIs dereference the pointer
-- even when length is 0).
withByteString :: ByteString -> (Ptr CUChar -> CSize -> IO a) -> IO a
withByteString bs f
  | BS.null bs = f emptyBufPtr 0
  | otherwise  = BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
      f (castPtr ptr) (fromIntegral len)

-- | A non-null, well-aligned, dangling pointer used for empty ByteStrings
-- (analogous to Rust's @NonNull::dangling()@).  This is always passed with
-- length 0 and is never dereferenced; it exists solely to satisfy C APIs
-- that reject NULL even when the buffer length is zero.
emptyBufPtr :: Ptr CUChar
emptyBufPtr = nullPtr `plusPtr` 1
{-# NOINLINE emptyBufPtr #-}

-- | Create a ByteString of a given size by filling it via an IO action.
-- The action receives a pointer to write into and should fill exactly @n@ bytes.
createByteString :: Int -> (Ptr CUChar -> IO ()) -> IO ByteString
createByteString n f = do
  fptr <- BSI.mallocByteString n
  withForeignPtr fptr $ \ptr -> fillBytes ptr 0 n
  withForeignPtr fptr $ \ptr -> f (castPtr ptr)
  return (BSI.BS fptr n)

-- | Create a ByteString with variable-length output. Allocates @maxLen@ bytes,
-- runs the action which writes the actual length to the size pointer, then
-- trims to the actual length. Returns Nothing on failure (rc /= 1).
createByteStringLen :: Int -> (Ptr CUChar -> Ptr CSize -> IO CInt) -> IO (Maybe ByteString)
createByteStringLen maxLen f = do
  fptr <- BSI.mallocByteString maxLen
  withForeignPtr fptr $ \ptr ->
    alloca $ \lenPtr -> do
      poke lenPtr 0  -- Initialize to 0 to avoid reading garbage on buggy C functions
      rc <- f (castPtr ptr) lenPtr
      if rc == 1
        then do
          actualLen <- peek lenPtr
          let actual = fromIntegral actualLen
          if actual > maxLen
            then return Nothing  -- Bounds check: reject if C returned more than allocated
            else return (Just (BSI.BS fptr actual))
        else return Nothing

-- | Pack a buffer allocated by BoringSSL (via OPENSSL_malloc) into a ByteString,
-- then free the original buffer with OPENSSL_free.
packOpenSSLBuffer :: Ptr (Ptr CUChar) -> Ptr CSize -> IO ByteString
packOpenSSLBuffer bufPtrPtr lenPtr = do
  bufPtr <- peek bufPtrPtr
  if bufPtr == nullPtr
    then return BS.empty
    else do
      len <- peek lenPtr
      BS.packCStringLen (castPtr bufPtr, fromIntegral len)
        `finally` c_OPENSSL_free bufPtr

-- | Constant-time equality comparison for ByteStrings of equal length.
-- Uses BoringSSL's CRYPTO_memcmp to avoid timing side-channel attacks.
-- Returns True if the two ByteStrings are equal, False otherwise.
--
-- Note: The length comparison itself is /not/ constant-time. If the
-- two inputs have different lengths, this returns @False@ immediately.
-- This is acceptable for fixed-length cryptographic values (MACs,
-- digests, keys of known size) but should not be relied upon to hide
-- length information.
constTimeEq :: ByteString -> ByteString -> Bool
constTimeEq a b
  | BS.length a /= BS.length b = False
  | otherwise = unsafePerformIO $
      BSU.unsafeUseAsCStringLen a $ \(ptrA, len) ->
        BSU.unsafeUseAsCStringLen b $ \(ptrB, _) -> do
          rc <- c_CRYPTO_memcmp ptrA ptrB (fromIntegral len)
          return (rc == 0)
