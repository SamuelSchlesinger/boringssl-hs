module Crypto.BoringSSL.Internal.Error
  ( CryptoError(..)
  , getBoringSSLError
  , clearBoringSSLError
  ) where

import Control.Exception (Exception)
import Crypto.BoringSSL.Internal.FFI
import Foreign.C.String
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

instance Exception CryptoError

-- | Clear the BoringSSL error queue for the current thread.
-- Should be called before operations where you want to inspect the
-- error queue afterwards, to avoid reading stale errors from prior
-- operations (especially relevant with GHC green threads that may
-- migrate between OS threads).
clearBoringSSLError :: IO ()
clearBoringSSLError = c_ERR_clear_error

-- | Drain the BoringSSL error queue and return the first error, if any.
getBoringSSLError :: IO (Maybe CryptoError)
getBoringSSLError = do
  errCode <- c_ERR_get_error
  if errCode == 0
    then return Nothing
    else do
      msg <- allocaArray 256 $ \buf -> do
        _ <- c_ERR_error_string_n errCode buf 256
        peekCString buf
      -- Drain remaining errors
      drainErrors
      return (Just (BoringSSLError (fromIntegral errCode) msg))

drainErrors :: IO ()
drainErrors = do
  e <- c_ERR_get_error
  if e == 0 then return () else drainErrors
