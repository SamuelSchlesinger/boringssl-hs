-- | PBKDF2 password-based key derivation (RFC 2898 \/ NIST SP 800-132).
--
-- Derives key material from a password and salt using iterated HMAC.
--
-- __Iteration count guidance:__
--
-- * OWASP (2023) recommends a minimum of 600,000 iterations with SHA-256,
--   or 210,000 with SHA-512.
-- * The iteration count should be as high as your application can tolerate
--   (targeting ~100ms–500ms of wall-clock time for interactive logins).
-- * Increase iterations over time as hardware improves.
--
-- __Salt requirements:__
--
-- * Use a cryptographically random salt of at least 16 bytes.
-- * Each password should have a unique salt; never reuse salts across users
--   or password changes.
--
-- __Algorithm choice:__ For new applications that can choose freely,
-- consider 'Crypto.BoringSSL.Scrypt.scrypt' which offers stronger resistance
-- to GPU\/ASIC attacks due to its memory-hard design. PBKDF2 is appropriate
-- when FIPS compliance or protocol interoperability is required.
module Crypto.BoringSSL.PBKDF2
  ( pbkdf2
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word32)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Internal.Buffer (withByteString)
import Crypto.BoringSSL.Internal.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.Internal.Digest as ID
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.PBKDF2
import Crypto.BoringSSL.Internal.SecureBytes

-- | Derive a key using PBKDF2-HMAC.
--
-- @pbkdf2 algo password salt iterations keyLength@ computes @keyLength@ bytes
-- of key material from @password@ and @salt@ using @iterations@ rounds of
-- PBKDF2 with HMAC using the specified hash @algo@.
pbkdf2 :: Algorithm -> ByteString -> ByteString -> Int -> Int -> Either CryptoError SecureBytes
pbkdf2 algo password salt iterations keyLen
  | keyLen <= 0 = Left (InvalidInput "pbkdf2: key length must be positive")
  | iterations <= 0 = Left (InvalidInput "pbkdf2: iterations must be positive")
  | iterations > fromIntegral (maxBound :: Word32) =
      Left (InvalidInput "pbkdf2: iterations exceeds uint32 maximum")
  | otherwise = unsafePerformIO $
  withByteString password $ \passPtr passLen ->
    withByteString salt $ \saltPtr saltLen -> do
      sb <- createSecureBytes keyLen $ \_ -> return ()
      rc <- withSecureBytes sb $ \outPtr _ ->
        c_PKCS5_PBKDF2_HMAC
                (castPtr passPtr) passLen
                saltPtr saltLen
                (fromIntegral iterations) (ID.evpMD algo)
                (fromIntegral keyLen) (castPtr outPtr)
      if rc /= 1
        then return (Left (OperationFailed "pbkdf2: PKCS5_PBKDF2_HMAC failed"))
        else return (Right sb)
{-# NOINLINE pbkdf2 #-}
