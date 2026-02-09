-- | Cryptographically secure random number generation.
--
-- Backed by BoringSSL's CSPRNG, which aborts the process on failure
-- rather than returning insecure output.
module Crypto.BoringSSL.Random
  ( randomBytes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.Random

-- | Generate @n@ cryptographically-secure random bytes.
-- BoringSSL aborts the process on CSPRNG failure, so this cannot fail.
-- @n@ must be non-negative; passing a negative value returns an empty
-- ByteString.
randomBytes :: Int -> IO ByteString
randomBytes n
  | n <= 0    = return BS.empty
  | otherwise = createByteString n $ \ptr -> do
      _ <- c_RAND_bytes ptr (fromIntegral n)
      return ()
