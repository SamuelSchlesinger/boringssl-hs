{-# LANGUAGE CApiFFI #-}
-- | Secure byte storage that zeroizes memory on finalization using
-- BoringSSL's @OPENSSL_cleanse@.
--
-- 'SecureBytes' is intended for private keys, shared secrets, and other
-- sensitive cryptographic material. When the garbage collector reclaims a
-- 'SecureBytes' value, the underlying memory is overwritten with zeros
-- before being freed, reducing the window during which secrets reside in
-- process memory.
--
-- /Caveats/:
--
--   * Haskell's garbage collector may copy memory during compaction,
--     leaving stale copies. 'SecureBytes' mitigates but does not
--     eliminate all exposure.
--
--   * 'secureBytesToByteString' creates a /non-cleansed/ copy; use it
--     only when you need interoperability with APIs that require
--     'ByteString'.
module Crypto.BoringSSL.Internal.SecureBytes
  ( SecureBytes
  , createSecureBytes
  , secureBytesToByteString
  , withSecureBytes
  , secureBytesLength
  , secureBytesEq
  , mallocSecureForeignPtr
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Foreign.C.Types
import qualified Foreign.Concurrent as FC
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.FFI.Memory (c_OPENSSL_cleanse, c_CRYPTO_memcmp)

-- | A block of memory that is zeroized (via @OPENSSL_cleanse@) when the
-- garbage collector finalizes it. Suitable for private keys, seeds,
-- and shared secrets.
data SecureBytes = SecureBytes
  { sbLength :: {-# UNPACK #-} !Int
  , sbFPtr   :: !(ForeignPtr CUChar)
  }

-- | Allocate @n@ bytes of secure memory, fill them via the callback, and
-- attach a finalizer that will @OPENSSL_cleanse@ then @free@ the buffer.
--
-- The callback receives a raw pointer to @n@ zero-initialized bytes and
-- should write the secret material into them.
createSecureBytes :: Int -> (Ptr CUChar -> IO ()) -> IO SecureBytes
createSecureBytes n f = do
  ptr <- mallocBytes n
  fillBytes ptr 0 n          -- zero-init for safety
  f (castPtr ptr)
  -- Use Foreign.Concurrent.newForeignPtr so we can capture @n@ and @ptr@
  -- in a Haskell closure. The finalizer cleanse + free in one action,
  -- avoiding ordering issues between C and Haskell finalizers.
  fptr <- FC.newForeignPtr (castPtr ptr) $ do
    c_OPENSSL_cleanse (castPtr ptr) (fromIntegral n)
    free ptr
  return (SecureBytes n fptr)

-- | Copy the secure bytes into a plain 'ByteString'.
--
-- __Warning__: the resulting 'ByteString' is /not/ zeroized on
-- finalization. Use this only when an API requires 'ByteString'.
secureBytesToByteString :: SecureBytes -> ByteString
secureBytesToByteString sb = unsafePerformIO $
  withSecureBytes sb $ \ptr len ->
    BS.packCStringLen (castPtr ptr, fromIntegral len)
{-# NOINLINE secureBytesToByteString #-}

-- | Temporarily access the raw pointer and length of the secure buffer.
-- The pointer is valid only for the duration of the callback.
withSecureBytes :: SecureBytes -> (Ptr CUChar -> CSize -> IO a) -> IO a
withSecureBytes (SecureBytes n fptr) f =
  withForeignPtr fptr $ \ptr -> f ptr (fromIntegral n)

-- | Return the length (in bytes) of the secure buffer.
secureBytesLength :: SecureBytes -> Int
secureBytesLength = sbLength

-- | Allocate @n@ bytes of memory that will be zeroized via
-- @OPENSSL_cleanse@ and then freed when the 'ForeignPtr' is finalized.
-- Use this for opaque C structs (e.g. post-quantum private key structs)
-- that contain secret material and need to be cleansed on GC.
mallocSecureForeignPtr :: Int -> IO (ForeignPtr ())
mallocSecureForeignPtr n = do
  ptr <- mallocBytes n
  fillBytes ptr 0 n
  FC.newForeignPtr ptr $ do
    c_OPENSSL_cleanse ptr (fromIntegral n)
    free ptr

-- | Constant-time equality comparison using BoringSSL's @CRYPTO_memcmp@.
-- Returns 'False' immediately (non-constant-time) if lengths differ,
-- which is acceptable for fixed-size cryptographic values.
secureBytesEq :: SecureBytes -> SecureBytes -> Bool
secureBytesEq a b
  | sbLength a /= sbLength b = False
  | otherwise = unsafePerformIO $
      withForeignPtr (sbFPtr a) $ \ptrA ->
        withForeignPtr (sbFPtr b) $ \ptrB -> do
          rc <- c_CRYPTO_memcmp ptrA ptrB (fromIntegral (sbLength a))
          return (rc == 0)
