module Crypto.BoringSSL.Internal.Buffer
  ( withByteString
  , createByteString
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr

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
