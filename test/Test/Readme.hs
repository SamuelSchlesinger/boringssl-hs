{-# LANGUAGE OverloadedStrings #-}
-- | The README's quick-start examples, compiled and executed.
--
-- The README previously drifted far enough from the API that its only
-- worked example did not compile. Keep these functions byte-for-byte in
-- sync with the code blocks in @README.md@ so that can never recur: if
-- the API changes under them, this module stops compiling.
module Test.Readme (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Error (CryptoError)
import Crypto.BoringSSL.SecureBytes (SecureBytes, secureBytesLength)
import qualified Crypto.BoringSSL.AEAD as AEAD
import qualified Crypto.BoringSSL.Digest as Digest
import qualified Crypto.BoringSSL.Random as Random
import qualified Crypto.BoringSSL.Scrypt as Scrypt

-- Hashing is pure and total.
digest :: ByteString
digest = Digest.hashSHA256 "hello, world"

-- Authenticated encryption with AES-256-GCM.
aeadExample :: IO ByteString
aeadExample = do
  key <- Random.randomBytes (AEAD.keyLength AEAD.AES256GCM)
  ctx <- either (error . show) pure =<< AEAD.newAEADCtx AEAD.AES256GCM key
  -- Never reuse a nonce with the same key.
  nonce <- AEAD.generateNonce AEAD.AES256GCM
  let ad = "associated data"        -- authenticated, not encrypted
  ciphertext <- either (error . show) pure (AEAD.seal ctx nonce "secret message" ad)
  case AEAD.open ctx nonce ciphertext ad of
    Left err        -> error (show err)   -- AuthenticationFailed if tampered
    Right plaintext -> pure plaintext     -- "secret message"

hashPassword :: ByteString -> IO (Either CryptoError SecureBytes)
hashPassword password = do
  salt <- Random.randomBytes 16
  pure (Scrypt.scrypt password salt Scrypt.defaultScryptParams)

tests :: TestTree
tests = testGroup "README examples"
  [ testCase "hash example produces a SHA-256 digest" $
      BS.length digest @?= Digest.digestSize Digest.SHA256
  , testCase "AEAD example round-trips" $ do
      plaintext <- aeadExample
      plaintext @?= "secret message"
  , testCase "password hashing example produces a key" $ do
      result <- hashPassword "correct horse battery staple"
      case result of
        Left err -> assertFailure ("scrypt failed: " ++ show err)
        Right sb -> secureBytesLength sb @?= Scrypt.scryptLength Scrypt.defaultScryptParams
  ]
