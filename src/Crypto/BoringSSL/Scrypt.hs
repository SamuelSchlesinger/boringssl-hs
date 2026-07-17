-- | Scrypt password-based key derivation (RFC 7914).
--
-- Derives key material from a password and salt using a memory-hard
-- algorithm that resists GPU and ASIC attacks.
--
-- __Parameter selection:__
--
-- * @N@ — CPU\/memory cost. Must be a power of 2. Higher values use more
--   memory (@N * r * 128@ bytes) and more CPU time. Typical values:
--
--     * @N = 2^14@ (16384) — interactive logins (~100ms)
--     * @N = 2^17@ (131072) or higher — file encryption, key storage
--
-- * @r@ — block size. Controls sequential memory-read size. @r = 8@ is
--   the standard recommendation from the original scrypt paper.
-- * @p@ — parallelization factor. @p = 1@ is typical; increasing @p@
--   multiplies CPU work without increasing peak memory.
--
-- __Salt requirements:__ Use a cryptographically random salt of at least
-- 16 bytes. Each password should have a unique salt.
--
-- __Example (interactive login):__
--
-- @
-- scrypt password salt defaultScryptParams { scryptN = 16384 }
-- @
module Crypto.BoringSSL.Scrypt
  ( scrypt
  , ScryptParams(..)
  , defaultScryptParams
  ) where

import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.Word (Word64)
import Foreign.Ptr (castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString)
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.Scrypt
import Crypto.BoringSSL.Internal.SecureBytes

-- | Scrypt tuning parameters, named so the cost factors cannot be
-- transposed. Start from 'defaultScryptParams'.
data ScryptParams = ScryptParams
  { scryptN      :: !Word64
    -- ^ CPU\/memory cost; must be a power of 2 (memory use is
    -- @N * r * 128@ bytes).
  , scryptR      :: !Word64
    -- ^ Block size; 8 is the standard recommendation.
  , scryptP      :: !Word64
    -- ^ Parallelization factor; 1 is typical.
  , scryptLength :: !Int
    -- ^ Number of bytes of key material to derive.
  } deriving (Eq, Show)

-- | OWASP's 2023 first-choice scrypt parameters: @N = 2^17@, @r = 8@,
-- @p = 1@ (128 MiB, suitable for interactive logins on servers), with a
-- 32-byte output.
defaultScryptParams :: ScryptParams
defaultScryptParams = ScryptParams
  { scryptN = 131072
  , scryptR = 8
  , scryptP = 1
  , scryptLength = 32
  }

-- | Derive a key using scrypt.
--
-- @scrypt password salt params@ computes 'scryptLength' bytes of key
-- material from @password@ and @salt@.
--
-- Returns 'Left' on failure (e.g. invalid parameters).
scrypt :: ByteString -> ByteString -> ScryptParams -> Either CryptoError SecureBytes
scrypt password salt (ScryptParams n r p keyLen)
  | keyLen <= 0 = Left (InvalidInput "scrypt: key length must be positive")
  | n < 2 || (n .&. (n - 1)) /= 0 = Left (InvalidInput "scrypt: N must be >= 2 and a power of 2")
  | r == 0 = Left (InvalidInput "scrypt: r must be > 0")
  | p == 0 = Left (InvalidInput "scrypt: p must be > 0")
  | otherwise = unsafePerformIO $
  withByteString password $ \passPtr passLen ->
    withByteString salt $ \saltPtr saltLen -> do
      sb <- createSecureBytes keyLen $ \_ -> return ()
      rc <- withSecureBytes sb $ \outPtr _ ->
        c_EVP_PBE_scrypt
          (castPtr passPtr) passLen
          saltPtr saltLen
          n r p 0
          (castPtr outPtr) (fromIntegral keyLen)
      if rc /= 1
        then return (Left (OperationFailed "scrypt: derivation failed"))
        else return (Right sb)
{-# NOINLINE scrypt #-}
