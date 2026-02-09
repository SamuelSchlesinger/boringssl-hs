module Crypto.BoringSSL.Internal.Buffer
  ( withByteString
  , createByteString
  , createByteStringLen
  , packOpenSSLBuffer
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_free)

-- | Use a ByteString as a C pointer and length. For empty ByteStrings,
-- passes a non-null pointer (nullPtr is avoided for safety with some C APIs).
withByteString :: ByteString -> (Ptr CUChar -> CSize -> IO a) -> IO a
withByteString bs f =
  BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    f (castPtr ptr) (fromIntegral len)

-- | Create a ByteString of a given size by filling it via an IO action.
-- The action receives a pointer to write into and should fill exactly @n@ bytes.
createByteString :: Int -> (Ptr CUChar -> IO ()) -> IO ByteString
createByteString n f = do
  fptr <- BSI.mallocByteString n
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
      rc <- f (castPtr ptr) lenPtr
      if rc == 1
        then do
          actualLen <- peek lenPtr
          return (Just (BSI.BS fptr (fromIntegral actualLen)))
        else return Nothing

-- | Pack a buffer allocated by BoringSSL (via OPENSSL_malloc) into a ByteString,
-- then free the original buffer with OPENSSL_free.
packOpenSSLBuffer :: Ptr (Ptr CUChar) -> Ptr CSize -> IO ByteString
packOpenSSLBuffer bufPtrPtr lenPtr = do
  bufPtr <- peek bufPtrPtr
  len <- peek lenPtr
  bs <- BS.packCStringLen (castPtr bufPtr, fromIntegral len)
  c_OPENSSL_free bufPtr
  return bs
