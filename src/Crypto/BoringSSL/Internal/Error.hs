module Crypto.BoringSSL.Internal.Error
  ( BoringSSLError(..)
  , getBoringSSLError
  , clearBoringSSLError
  ) where

import Control.Exception (Exception)
import Crypto.BoringSSL.Internal.FFI
import Foreign.C.String
import Foreign.Marshal.Array

-- | An error from the BoringSSL error queue.
data BoringSSLError = BoringSSLError
  { errorCode    :: !Int
  , errorMessage :: !String
  } deriving (Eq)

instance Show BoringSSLError where
  show (BoringSSLError code msg) =
    "BoringSSLError " ++ show code ++ ": " ++ msg

instance Exception BoringSSLError

-- | Clear the BoringSSL error queue for the current thread.
-- Should be called before operations where you want to inspect the
-- error queue afterwards, to avoid reading stale errors from prior
-- operations (especially relevant with GHC green threads that may
-- migrate between OS threads).
clearBoringSSLError :: IO ()
clearBoringSSLError = c_ERR_clear_error

-- | Drain the BoringSSL error queue and return the first error, if any.
getBoringSSLError :: IO (Maybe BoringSSLError)
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
