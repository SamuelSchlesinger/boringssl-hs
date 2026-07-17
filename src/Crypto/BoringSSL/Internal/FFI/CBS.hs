{-# LANGUAGE CApiFFI #-}
-- | FFI bindings for CBS (BoringSSL Crypto ByteString) helpers.
--
-- These helpers avoid manual struct layout assumptions in Haskell
-- by delegating CBS initialization to C.
module Crypto.BoringSSL.Internal.FFI.CBS
  ( -- * Opaque types
    CBS
  , CBB
    -- * CBS helpers
  , c_bssl_CBS_init
  , c_bssl_CBS_size
    -- * CBB helpers
  , c_bssl_CBB_init_fixed
  , c_bssl_CBB_size
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

-- | Opaque CBB struct type. Haskell code should never inspect its layout.
data CBB

-- | Initialize a fixed-buffer CBB writing to @len@ bytes at @buf@.
-- Fixed CBBs allocate nothing, so no cleanup call is required.
foreign import capi unsafe "cbs_helpers.h bssl_CBB_init_fixed"
  c_bssl_CBB_init_fixed :: Ptr CBB -> Ptr CUChar -> CSize -> IO ()

-- | @sizeof(CBB)@ for stack allocation.
foreign import capi unsafe "cbs_helpers.h bssl_CBB_size"
  c_bssl_CBB_size_io :: IO CSize

-- | The size of a CBB struct, as a pure value.
c_bssl_CBB_size :: Int
c_bssl_CBB_size = fromIntegral (unsafePerformIO c_bssl_CBB_size_io)
{-# NOINLINE c_bssl_CBB_size #-}
