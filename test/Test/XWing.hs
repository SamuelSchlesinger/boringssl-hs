{-# LANGUAGE OverloadedStrings #-}
module Test.XWing (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.XWing

tests :: TestTree
tests = testGroup "XWing"
  [ testCase "keygen produces 1216-byte public key" $ do
      Right (pub, _priv) <- generateKeyPair
      BS.length pub @?= 1216

  , testCase "publicFromPrivate matches keygen" $ do
      Right (pub, priv) <- generateKeyPair
      Right pub2 <- publicFromPrivate priv
      pub2 @?= pub

  , testCase "encapsulate/decapsulate round-trip" $ do
      Right (pub, priv) <- generateKeyPair
      Right (ct, ss1) <- encapsulate pub
      Right ss2 <- decapsulate priv ct
      secureBytesToByteString ss1 @?= secureBytesToByteString ss2
      secureBytesLength ss1 @?= 32

  , testCase "ciphertext is 1120 bytes" $ do
      Right (pub, _priv) <- generateKeyPair
      Right (ct, _ss) <- encapsulate pub
      BS.length ct @?= 1120

  , testCase "different encapsulations produce different shared secrets" $ do
      Right (pub, priv) <- generateKeyPair
      Right (ct1, ss1) <- encapsulate pub
      Right (ct2, ss2) <- encapsulate pub
      let ss1bs = secureBytesToByteString ss1
          ss2bs = secureBytesToByteString ss2
      assertBool "shared secrets should differ" (ss1bs /= ss2bs)
      assertBool "ciphertexts should differ" (ct1 /= ct2)
      -- Both should still decapsulate correctly
      Right dec1 <- decapsulate priv ct1
      Right dec2 <- decapsulate priv ct2
      secureBytesToByteString dec1 @?= ss1bs
      secureBytesToByteString dec2 @?= ss2bs

  , testCase "wrong private key produces different shared secret" $ do
      Right (pub, _priv1) <- generateKeyPair
      Right (_pub2, priv2) <- generateKeyPair
      Right (ct, ss1) <- encapsulate pub
      Right ss2 <- decapsulate priv2 ct
      assertBool "wrong key should produce different shared secret"
        (secureBytesToByteString ss1 /= secureBytesToByteString ss2)

  , testCase "encapsulate rejects wrong-length public key" $ do
      result <- encapsulate "too short"
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "encapsulate should reject wrong-length public key"

  , testCase "decapsulate rejects wrong-length ciphertext" $ do
      Right (_pub, priv) <- generateKeyPair
      result <- decapsulate priv "too short"
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "decapsulate should reject wrong-length ciphertext"
  ]
