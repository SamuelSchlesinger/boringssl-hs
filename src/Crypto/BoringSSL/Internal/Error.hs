module Crypto.BoringSSL.Internal.Error
  ( CryptoError(..)
  , getBoringSSLError
  , clearBoringSSLError
  , withBoundThread
  ) where

import Control.Concurrent (rtsSupportsBoundThreads, runInBoundThread)
import Control.Exception (Exception)
import Data.List (intercalate)
import Crypto.BoringSSL.Internal.FFI
import Foreign.C.String
import Foreign.C.Types
import Foreign.Marshal.Array

-- | Errors that can occur in the boringssl library.
data CryptoError
  = BoringSSLError !Int !String
    -- ^ A genuine error from the BoringSSL error queue, with the
    -- packed error code and human-readable message.
  | InvalidInput !String
    -- ^ Haskell-side input validation rejected the arguments before
    -- any C function was called (e.g. wrong key length).
  | AllocationFailure !String
    -- ^ A C allocation function (@_new@, @malloc@) returned @NULL@.
  | OperationFailed !String
    -- ^ A C operation returned a failure code but the BoringSSL error
    -- queue was empty or was not consulted.
  | DecodeError !String
    -- ^ Parsing or deserialization of input data failed.
  | AuthenticationFailed
    -- ^ Authenticated decryption rejected the input: the authentication
    -- tag did not verify, meaning the ciphertext or associated data was
    -- tampered with (or the wrong key\/nonce was used). Distinct from
    -- 'InvalidInput' so callers can tell tampering from their own bugs.
  deriving (Eq)

instance Show CryptoError where
  show (BoringSSLError code msg) =
    "BoringSSLError " ++ show code ++ ": " ++ msg
  show (InvalidInput msg) =
    "InvalidInput: " ++ msg
  show (AllocationFailure msg) =
    "AllocationFailure: " ++ msg
  show (OperationFailed msg) =
    "OperationFailed: " ++ msg
  show (DecodeError msg) =
    "DecodeError: " ++ msg
  show AuthenticationFailed =
    "AuthenticationFailed: authentication tag mismatch (tampered input or wrong key/nonce)"

instance Exception CryptoError

-- | Clear the BoringSSL error queue for the current thread.
-- Should be called before operations where you want to inspect the
-- error queue afterwards, to avoid reading stale errors from prior
-- operations (especially relevant with GHC green threads that may
-- migrate between OS threads).
clearBoringSSLError :: IO ()
clearBoringSSLError = c_ERR_clear_error

-- | Drain the BoringSSL error queue and return all errors, if any.
-- The error code is taken from the first error, and all error messages
-- are concatenated (separated by "; ") into a single string.
getBoringSSLError :: IO (Maybe CryptoError)
getBoringSSLError = do
  errCode <- c_ERR_get_error
  if errCode == 0
    then return Nothing
    else do
      msgs <- collectErrors errCode []
      return (Just (BoringSSLError (fromIntegral errCode) (intercalate "; " (reverse msgs))))

collectErrors :: CUInt -> [String] -> IO [String]
collectErrors code acc = do
  msg <- allocaArray 512 $ \buf -> do
    c_ERR_error_string_n code buf 512
    peekCString buf
  nextCode <- c_ERR_get_error
  if nextCode == 0
    then return (msg : acc)
    else collectErrors nextCode (msg : acc)

-- | Pin an IO action to a single OS thread using 'runInBoundThread'.
-- BoringSSL's error queue is per-OS-thread, but GHC green threads can
-- migrate between OS threads at safe FFI call boundaries.  Wrapping the
-- @clearBoringSSLError@ / C call / @getBoringSSLError@ sequence with
-- 'withBoundThread' guarantees all three run on the same OS thread,
-- preventing error misattribution.
--
-- With the non-threaded RTS there is only one OS thread, so migration
-- cannot occur and 'runInBoundThread' is unnecessary (and would crash).
withBoundThread :: IO a -> IO a
withBoundThread
  | rtsSupportsBoundThreads = runInBoundThread
  | otherwise               = id
