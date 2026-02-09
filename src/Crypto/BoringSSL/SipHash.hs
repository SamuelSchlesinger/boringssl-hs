-- | SipHash-2-4, a fast secure pseudorandom function.
--
-- Commonly used for hash table hashing. See
-- <https://131002.net/siphash/siphash.pdf>.
module Crypto.BoringSSL.SipHash
  ( sipHash24
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word64)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Ptr (castPtr)
import Foreign.Storable (pokeElemOff)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.SipHash

-- | Compute SipHash-2-4.
--
-- @sipHash24 (k0, k1) input@ computes SipHash-2-4 of @input@ using
-- the 128-bit key given as two 'Word64' values.
sipHash24 :: (Word64, Word64) -> ByteString -> Word64
sipHash24 (k0, k1) input = unsafePerformIO $
  allocaArray 2 $ \keyPtr -> do
    pokeElemOff keyPtr 0 k0
    pokeElemOff keyPtr 1 k1
    withByteString input $ \inputPtr inputLen ->
      c_SIPHASH_24 keyPtr (castPtr inputPtr) inputLen
{-# NOINLINE sipHash24 #-}
