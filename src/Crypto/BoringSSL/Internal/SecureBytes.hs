{-# LANGUAGE CApiFFI #-}
-- | Secure byte storage for private keys, shared secrets, and other
-- sensitive cryptographic material.
--
-- Buffers are allocated page-aligned outside the GC heap, locked into RAM
-- on a best-effort basis (@mlock@ on POSIX, @VirtualLock@ on Windows,
-- proceeding unlocked if the platform limit is exhausted), excluded from
-- core dumps where supported (@MADV_DONTDUMP@), and overwritten with
-- zeros via BoringSSL's @OPENSSL_cleanse@ before being released.
--
-- __Threat model__ (what this does and does not protect against):
--
--   * Zero-on-free protects against secrets lingering in reusable heap
--     memory and appearing in memory dumps taken after the value dies.
--   * Locking keeps secrets out of swap; dump exclusion keeps them out of
--     core dumps. Both are best-effort.
--   * None of this protects against a same-or-higher-privilege process
--     reading live memory, DMA or cold-boot attacks, hibernation images,
--     or copies /you/ make: 'secureBytesToByteString' produces an
--     ordinary GC-managed, non-cleansed copy, and any API that accepts or
--     returns a plain 'Data.ByteString.ByteString' moves the secret into
--     unprotected memory.
--
-- The 'Eq' instance is constant-time ('secureBytesEq'); the 'Show'
-- instance reveals only the length.
module Crypto.BoringSSL.Internal.SecureBytes
  ( SecureBytes
  , createSecureBytes
  , secureBytesToByteString
  , withSecureBytes
  , secureBytesLength
  , secureBytesEq
  , mallocSecureForeignPtr
  ) where

import Control.Exception (throwIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Foreign.C.Types
import qualified Foreign.Concurrent as FC
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Error (CryptoError (..))
import Crypto.BoringSSL.Internal.FFI.Memory (c_CRYPTO_memcmp)

-- | void *bssl_hs_secure_alloc(size_t len)
foreign import capi unsafe "secure_alloc.h bssl_hs_secure_alloc"
  c_bssl_hs_secure_alloc :: CSize -> IO (Ptr a)

-- | void bssl_hs_secure_free(void *ptr, size_t len)
foreign import capi unsafe "secure_alloc.h bssl_hs_secure_free"
  c_bssl_hs_secure_free :: Ptr a -> CSize -> IO ()

-- | A block of hardened memory (see the module header for the exact
-- guarantees) that is cleansed when the garbage collector finalizes it.
-- Suitable for private keys, seeds, and shared secrets.
data SecureBytes = SecureBytes
  { sbLength :: {-# UNPACK #-} !Int
  , sbFPtr   :: !(ForeignPtr CUChar)
  }

-- | Constant-time comparison; the length check short-circuits, which is
-- acceptable for fixed-size cryptographic values.
instance Eq SecureBytes where
  (==) = secureBytesEq

-- | Reveals only the length, never the contents.
instance Show SecureBytes where
  show sb = "SecureBytes[" ++ show (sbLength sb) ++ " bytes]"

-- | Allocate a secure buffer (see module header), fill it via the
-- callback, and attach a finalizer that cleanses and releases it.
--
-- The callback receives a pointer to @n@ zero-initialized bytes and
-- should write the secret material into them. Throws 'AllocationFailure'
-- if the underlying mapping cannot be created.
createSecureBytes :: Int -> (Ptr CUChar -> IO ()) -> IO SecureBytes
createSecureBytes n f = do
  ptr <- c_bssl_hs_secure_alloc (fromIntegral n)
  if ptr == nullPtr
    then throwIO (AllocationFailure "createSecureBytes: secure allocation failed")
    else pure ()
  f ptr
  fptr <- FC.newForeignPtr (castPtr ptr) $
    c_bssl_hs_secure_free ptr (fromIntegral n)
  return (SecureBytes n fptr)

-- | Copy the secure bytes into a plain 'ByteString'.
--
-- __Warning__: the resulting 'ByteString' is an ordinary GC-managed
-- value — never locked, never cleansed. Use this only at the boundary
-- with APIs that require 'ByteString', and treat the copy as leaked.
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

-- | Allocate @n@ bytes of secure memory (same guarantees as
-- 'SecureBytes') that will be cleansed and released when the
-- 'ForeignPtr' is finalized. Use this for opaque C structs (e.g.
-- post-quantum private key structs) that contain secret material.
-- Throws 'AllocationFailure' if the mapping cannot be created.
mallocSecureForeignPtr :: Int -> IO (ForeignPtr ())
mallocSecureForeignPtr n = do
  ptr <- c_bssl_hs_secure_alloc (fromIntegral n)
  if ptr == nullPtr
    then throwIO (AllocationFailure "mallocSecureForeignPtr: secure allocation failed")
    else pure ()
  FC.newForeignPtr ptr $
    c_bssl_hs_secure_free ptr (fromIntegral n)

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
{-# NOINLINE secureBytesEq #-}
