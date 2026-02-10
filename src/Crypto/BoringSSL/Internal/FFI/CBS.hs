{-# LANGUAGE CApiFFI #-}
-- | FFI bindings for CBS (BoringSSL Crypto ByteString) helpers.
--
-- These helpers avoid manual struct layout assumptions in Haskell
-- by delegating CBS initialization to C.
module Crypto.BoringSSL.Internal.FFI.CBS
  ( -- * Opaque type
    CBS
    -- * CBS helpers
  , c_bssl_CBS_init
  , c_bssl_CBS_size
  ) where

import Foreign.C.Types
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

-- | Opaque CBS struct type. Haskell code should never inspect its layout.
data CBS

-- | Initialize a CBS from a data pointer and length.
foreign import capi unsafe "cbs_helpers.h bssl_CBS_init"
  c_bssl_CBS_init :: Ptr CBS -> Ptr CUChar -> CSize -> IO ()

-- | Return @sizeof(CBS)@ so Haskell can allocate the right amount of
-- stack space with 'Foreign.Marshal.Alloc.allocaBytes'.
foreign import capi unsafe "cbs_helpers.h bssl_CBS_size"
  c_bssl_CBS_size_io :: IO CSize

-- | The size of a CBS struct, as a pure value.
-- This is safe because @sizeof(CBS)@ is a compile-time constant.
c_bssl_CBS_size :: Int
c_bssl_CBS_size = fromIntegral (unsafePerformIO c_bssl_CBS_size_io)
{-# NOINLINE c_bssl_CBS_size #-}
