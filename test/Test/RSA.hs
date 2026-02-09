{-# LANGUAGE OverloadedStrings #-}
module Test.RSA (tests) where

import qualified Data.ByteString as BS
import Control.Exception (try, SomeException)
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..), hashSHA256)
import Crypto.BoringSSL.RSA

tests :: TestTree
tests = testGroup "RSA"
  [ testCase "key generation (2048-bit)" $ do
      kp <- generateRSAKeyPair 2048
      bits <- rsaBits kp
      bits @?= 2048
      size <- rsaSize kp
      size @?= 256
  , testGroup "PKCS#1 v1.5"
    [ testCase "sign/verify round-trip" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        let digest = hashSHA256 "Hello, RSA!"
        Right sig <- rsaSign kp SHA256 digest
        valid <- rsaVerify pub SHA256 digest sig
        assertBool "signature should verify" valid
    , testCase "wrong digest rejected" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        let digest1 = hashSHA256 "message A"
            digest2 = hashSHA256 "message B"
        Right sig <- rsaSign kp SHA256 digest1
        valid <- rsaVerify pub SHA256 digest2 sig
        assertBool "wrong digest should not verify" (not valid)
    ]
  , testGroup "PSS"
    [ testCase "sign/verify round-trip" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        let digest = hashSHA256 "Hello, RSA-PSS!"
        Right sig <- rsaSignPSS kp SHA256 digest
        valid <- rsaVerifyPSS pub SHA256 digest sig
        assertBool "PSS signature should verify" valid
    ]
  , testGroup "OAEP"
    [ testCase "encrypt/decrypt round-trip" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        let plaintext = "Hello, RSA-OAEP!"
        Right ct <- rsaEncrypt pub plaintext
        Right recovered <- rsaDecrypt kp ct
        recovered @?= plaintext
    , testCase "max plaintext length" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        -- RSA-OAEP with SHA-1 (default): max = modulus_size - 2*hash_size - 2
        -- = 256 - 2*20 - 2 = 214 bytes
        let plaintext = BS.replicate 214 0x42
        Right ct <- rsaEncrypt pub plaintext
        Right recovered <- rsaDecrypt kp ct
        recovered @?= plaintext
    ]
  , testGroup "Safety"
    [ testCase "rejects key size below 2048" $ do
        result <- try (generateRSAKeyPair 1024) :: IO (Either SomeException RSAKeyPair)
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 1024-bit key"
    , testCase "rejects key size of 512" $ do
        result <- try (generateRSAKeyPair 512) :: IO (Either SomeException RSAKeyPair)
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 512-bit key"
    ]
  , testGroup "Serialization"
    [ testCase "public key round-trip" $ do
        kp <- generateRSAKeyPair 2048
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        -- Verify the deserialized key works
        let digest = hashSHA256 "serialization test"
        Right sig <- rsaSign kp SHA256 digest
        valid <- rsaVerify pub SHA256 digest sig
        assertBool "deserialized key should work" valid
    , testCase "private key round-trip" $ do
        kp <- generateRSAKeyPair 2048
        privBytes <- privateKeyToBytes kp
        kp2 <- privateKeyFromBytes privBytes
        pubBytes <- publicKeyToBytes kp
        pub <- publicKeyFromBytes pubBytes
        -- Sign with deserialized private key, verify with original public key
        let digest = hashSHA256 "private key serialization test"
        Right sig <- rsaSign kp2 SHA256 digest
        valid <- rsaVerify pub SHA256 digest sig
        assertBool "deserialized private key should work" valid
    ]
  ]
