{-# LANGUAGE OverloadedStrings #-}
module Test.PrivateKey (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.PrivateKey
import Crypto.BoringSSL.RSA (generateRSAKeyPair, privateKeyToBytes)
import Crypto.BoringSSL.ECDH (ECCurve(..), generateECKeyPair, ecPrivateKeyBytes)
import Crypto.BoringSSL.PEM (pemEncode)

tests :: TestTree
tests = testGroup "PrivateKey"
  [ testCase "RSA DER round-trip" $ do
      Right kp <- generateRSAKeyPair 2048
      Right privBytes <- privateKeyToBytes kp
      result <- pure $ loadPrivateKeyDER privBytes
      case result of
        Right (SomeRSAKey _) -> return ()
        Right other -> assertFailure ("expected RSA key, got: " ++ show other)
        Left err -> assertFailure ("loadPrivateKeyDER failed: " ++ show err)

  , testCase "RSA PEM round-trip" $ do
      Right kp <- generateRSAKeyPair 2048
      Right privBytes <- privateKeyToBytes kp
      pem <- case pemEncode "RSA PRIVATE KEY" privBytes of
        Left err -> assertFailure ("pemEncode failed: " ++ show err) >> error "unreachable"
        Right p -> return p
      result <- pure $ loadPrivateKeyPEM pem
      case result of
        Right (SomeRSAKey _) -> return ()
        Right other -> assertFailure ("expected RSA key, got: " ++ show other)
        Left err -> assertFailure ("loadPrivateKeyPEM failed: " ++ show err)

  , testCase "garbage DER rejected" $ do
      result <- pure $ loadPrivateKeyDER (BS.replicate 32 0xFF)
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "should reject garbage DER"

  , testCase "garbage PEM rejected" $ do
      result <- pure $ loadPrivateKeyPEM "not a pem"
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "should reject garbage PEM"

  , testCase "EC key private bytes are reasonable" $ do
      Right _kp <- generateECKeyPair P256
      Right privBytes <- ecPrivateKeyBytes _kp
      assertBool "EC private key bytes should be 32 bytes for P-256" (BS.length privBytes == 32)
      assertBool "EC private key bytes should not be all zeros" (privBytes /= BS.replicate 32 0)
  ]
