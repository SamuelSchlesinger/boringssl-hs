-- | Cryptographically secure random number generation.
--
-- Backed by BoringSSL's CSPRNG, which aborts the process on failure
-- rather than returning insecure output.
module Crypto.BoringSSL.Random
  ( randomBytes
  , randomSecureBytes
  ) where

import Control.Exception (throwIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error (CryptoError (..))
import Crypto.BoringSSL.Internal.FFI.Random
import Crypto.BoringSSL.Internal.SecureBytes (SecureBytes, createSecureBytes)

-- | Generate @n@ cryptographically-secure random bytes.
-- BoringSSL aborts the process on CSPRNG failure, so this cannot return
-- insecure output. Throws 'InvalidInput' if @n@ is negative.
randomBytes :: Int -> IO ByteString
randomBytes n
  | n < 0     = throwIO (InvalidInput "randomBytes: negative length")
  | n == 0    = return BS.empty
  | otherwise = createByteString n $ \ptr -> do
      _ <- c_RAND_bytes ptr (fromIntegral n)
      return ()

-- | Generate @n@ cryptographically-secure random bytes directly into
-- hardened 'SecureBytes' storage, so key material is never exposed in an
-- ordinary GC-managed buffer. Prefer this over 'randomBytes' when
-- generating keys, seeds, or other secrets. Throws 'InvalidInput' if @n@
-- is negative.
randomSecureBytes :: Int -> IO SecureBytes
randomSecureBytes n
  | n < 0     = throwIO (InvalidInput "randomSecureBytes: negative length")
  | otherwise = createSecureBytes n $ \ptr -> do
      _ <- c_RAND_bytes ptr (fromIntegral n)
      return ()
