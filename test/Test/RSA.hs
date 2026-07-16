{-# LANGUAGE OverloadedStrings #-}
-- rsaEncryptPKCS1/rsaDecryptPKCS1 are deprecated but still shipped, so we
-- keep test coverage for them.
{-# OPTIONS_GHC -Wno-deprecations #-}
module Test.RSA (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..), hashSHA256)
import Crypto.BoringSSL.RSA

tests :: TestTree
tests = testGroup "RSA"
  [ testCase "key generation (2048-bit)" $ do
      Right kp <- generateRSAKeyPair 2048
      bits <- rsaBits kp
      bits @?= 2048
      size <- rsaSize kp
      size @?= 256
  , testGroup "PKCS#1 v1.5"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let digest = hashSHA256 "Hello, RSA!"
        Right sig <- rsaSign kp SHA256 digest
        Right valid <- rsaVerify pub SHA256 digest sig
        assertBool "signature should verify" valid
    , testCase "wrong digest rejected" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let digest1 = hashSHA256 "message A"
            digest2 = hashSHA256 "message B"
        Right sig <- rsaSign kp SHA256 digest1
        Right valid <- rsaVerify pub SHA256 digest2 sig
        assertBool "wrong digest should not verify" (not valid)
    ]
  , testGroup "PSS"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let digest = hashSHA256 "Hello, RSA-PSS!"
        Right sig <- rsaSignPSS kp SHA256 digest
        Right valid <- rsaVerifyPSS pub SHA256 digest sig
        assertBool "PSS signature should verify" valid
    , testCase "wrong digest rejected" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let digest1 = hashSHA256 "message A"
            digest2 = hashSHA256 "message B"
        Right sig <- rsaSignPSS kp SHA256 digest1
        Right valid <- rsaVerifyPSS pub SHA256 digest2 sig
        assertBool "wrong digest should not verify" (not valid)
    ]
  , testGroup "OAEP"
    [ testCase "encrypt/decrypt round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let plaintext = "Hello, RSA-OAEP!"
        Right ct <- rsaEncrypt pub plaintext
        Right recovered <- rsaDecrypt kp ct
        recovered @?= plaintext
    , testCase "max plaintext length" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        -- RSA-OAEP with SHA-1 (default): max = modulus_size - 2*hash_size - 2
        -- = 256 - 2*20 - 2 = 214 bytes
        let plaintext = BS.replicate 214 0x42
        Right ct <- rsaEncrypt pub plaintext
        Right recovered <- rsaDecrypt kp ct
        recovered @?= plaintext
    , testCase "too-long plaintext returns Left" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let plaintext = BS.replicate 215 0x42  -- one byte over max
        result <- rsaEncrypt pub plaintext
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject too-long plaintext"
    ]
  , testGroup "Safety"
    [ testCase "rejects key size below 2048" $ do
        result <- generateRSAKeyPair 1024
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 1024-bit key"
    , testCase "rejects key size of 512" $ do
        result <- generateRSAKeyPair 512
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 512-bit key"
    ]
  , testGroup "Serialization"
    [ testCase "public key round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        -- Verify the deserialized key works
        let digest = hashSHA256 "serialization test"
        Right sig <- rsaSign kp SHA256 digest
        Right valid <- rsaVerify pub SHA256 digest sig
        assertBool "deserialized key should work" valid
    , testCase "private key round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right privBytes <- privateKeyToBytes kp
        Right kp2 <- privateKeyFromBytes privBytes
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        -- Sign with deserialized private key, verify with original public key
        let digest = hashSHA256 "private key serialization test"
        Right sig <- rsaSign kp2 SHA256 digest
        Right valid <- rsaVerify pub SHA256 digest sig
        assertBool "deserialized private key should work" valid
    , testCase "publicKeyFromBytes rejects garbage" $ do
        result <- publicKeyFromBytes (BS.replicate 32 0xFF)
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject garbage bytes"
    , testCase "privateKeyFromBytes rejects garbage" $ do
        result <- privateKeyFromBytes (BS.replicate 32 0xFF)
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject garbage bytes"
    ]
  , testGroup "PKCS#1 v1.5 encryption"
    [ testCase "encrypt/decrypt round-trip" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let plaintext = "Hello, PKCS1!"
        Right ct <- rsaEncryptPKCS1 pub plaintext
        Right recovered <- rsaDecryptPKCS1 kp ct
        recovered @?= plaintext
    , testCase "max plaintext (245 bytes for 2048-bit key)" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        -- PKCS#1 v1.5: max = modulus_size - 11 = 256 - 11 = 245
        let plaintext = BS.replicate 245 0x42
        Right ct <- rsaEncryptPKCS1 pub plaintext
        Right recovered <- rsaDecryptPKCS1 kp ct
        recovered @?= plaintext
    , testCase "too-long plaintext returns Left" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        let plaintext = BS.replicate 246 0x42
        result <- rsaEncryptPKCS1 pub plaintext
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject too-long plaintext"
    ]
  , testGroup "public key properties"
    [ testCase "rsaPublicBits matches rsaBits" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        bits <- rsaBits kp
        pubBits <- rsaPublicBits pub
        pubBits @?= bits
    , testCase "rsaPublicSize matches rsaSize" $ do
        Right kp <- generateRSAKeyPair 2048
        Right pubBytes <- publicKeyToBytes kp
        Right pub <- publicKeyFromBytes pubBytes
        size <- rsaSize kp
        pubSize <- rsaPublicSize pub
        pubSize @?= size
    ]
  , testGroup "signature size"
    [ testCase "PKCS#1 v1.5 signature is rsaSize bytes" $ do
        Right kp <- generateRSAKeyPair 2048
        size <- rsaSize kp
        let digest = hashSHA256 "test"
        Right sig <- rsaSign kp SHA256 digest
        BS.length sig @?= size
    , testCase "PSS signature is rsaSize bytes" $ do
        Right kp <- generateRSAKeyPair 2048
        size <- rsaSize kp
        let digest = hashSHA256 "test"
        Right sig <- rsaSignPSS kp SHA256 digest
        BS.length sig @?= size
    ]
  ]
