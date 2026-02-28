{-# LANGUAGE OverloadedStrings #-}
module Test.ECDSA (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (hashSHA256, hashSHA384, hashSHA512)
import Crypto.BoringSSL.ECDSA

tests :: TestTree
tests = testGroup "ECDSA"
  [ testGroup "P-256"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateKeyPair P256
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "Hello, ECDSA P-256!"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    , testCase "invalid signature rejected" $ do
        Right kp <- generateKeyPair P256
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "Hello, ECDSA P-256!"
        Right sig <- ecdsaSign kp digest
        let badSig = BS.replicate (BS.length sig) 0x00
        Right valid <- ecdsaVerify pub digest badSig
        assertBool "bad signature should not verify" (not valid)
    , testCase "wrong digest rejected" $ do
        Right kp <- generateKeyPair P256
        Right pub <- ecPublicKeyOfPair kp
        let digest1 = hashSHA256 "message A"
            digest2 = hashSHA256 "message B"
        Right sig <- ecdsaSign kp digest1
        Right valid <- ecdsaVerify pub digest2 sig
        assertBool "wrong digest should not verify" (not valid)
    , testCase "key serialization round-trip" $ do
        Right kp <- generateKeyPair P256
        Right pubBytes <- ecPublicKeyBytes kp
        Right privBytes <- ecPrivateKeyBytes kp
        -- Round-trip private key
        Right kp2 <- ecKeyPairFromPrivateBytes P256 privBytes
        Right privBytes2 <- ecPrivateKeyBytes kp2
        privBytes2 @?= privBytes
        -- Round-trip public key
        Right pub <- ecPublicKeyFromBytes P256 pubBytes
        let digest = hashSHA256 "round-trip test"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature from original key should verify with deserialized public key" valid
    ]
  , testGroup "P-256 P1363"
    [ testCase "sign/verify P1363 round-trip" $ do
        Right kp <- generateKeyPair P256
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "Hello, ECDSA P-256 P1363!"
        Right sig <- ecdsaSignP1363 kp digest
        Right valid <- ecdsaVerifyP1363 pub digest sig
        assertBool "P1363 signature should verify" valid
    , testCase "P1363 signature size is 64 bytes" $ do
        Right kp <- generateKeyPair P256
        let digest = hashSHA256 "test"
        Right sig <- ecdsaSignP1363 kp digest
        BS.length sig @?= 64
    , testCase "P1363 invalid signature rejected" $ do
        Right kp <- generateKeyPair P256
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "test"
            badSig = BS.replicate 64 0x00
        Right valid <- ecdsaVerifyP1363 pub digest badSig
        assertBool "bad P1363 signature should not verify" (not valid)
    ]
  , testCase "cross-key verification failure (P-256)" $ do
      Right kpA <- generateKeyPair P256
      Right kpB <- generateKeyPair P256
      Right pubB <- ecPublicKeyOfPair kpB
      let digest = hashSHA256 "cross-key test"
      Right sig <- ecdsaSign kpA digest
      Right valid <- ecdsaVerify pubB digest sig
      assertBool "signature from key A should not verify with key B" (not valid)
  , testGroup "P-384"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateKeyPair P384
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA384 "Hello, ECDSA P-384!"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    , testCase "invalid signature rejected" $ do
        Right kp <- generateKeyPair P384
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA384 "test"
        Right sig <- ecdsaSign kp digest
        let badSig = BS.replicate (BS.length sig) 0x00
        Right valid <- ecdsaVerify pub digest badSig
        assertBool "bad signature should not verify" (not valid)
    , testCase "sign/verify P1363 round-trip" $ do
        Right kp <- generateKeyPair P384
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA384 "Hello, ECDSA P-384 P1363!"
        Right sig <- ecdsaSignP1363 kp digest
        Right valid <- ecdsaVerifyP1363 pub digest sig
        assertBool "P1363 signature should verify" valid
    , testCase "P1363 signature size is 96 bytes" $ do
        Right kp <- generateKeyPair P384
        let digest = hashSHA384 "test"
        Right sig <- ecdsaSignP1363 kp digest
        BS.length sig @?= 96
    , testCase "key serialization round-trip" $ do
        Right kp <- generateKeyPair P384
        Right pubBytes <- ecPublicKeyBytes kp
        Right privBytes <- ecPrivateKeyBytes kp
        Right kp2 <- ecKeyPairFromPrivateBytes P384 privBytes
        Right privBytes2 <- ecPrivateKeyBytes kp2
        privBytes2 @?= privBytes
        Right pub <- ecPublicKeyFromBytes P384 pubBytes
        let digest = hashSHA384 "round-trip test"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify with deserialized public key" valid
    ]
  , testGroup "P-521"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateKeyPair P521
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA512 "Hello, ECDSA P-521!"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    , testCase "invalid signature rejected" $ do
        Right kp <- generateKeyPair P521
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA512 "test"
        Right sig <- ecdsaSign kp digest
        let badSig = BS.replicate (BS.length sig) 0x00
        Right valid <- ecdsaVerify pub digest badSig
        assertBool "bad signature should not verify" (not valid)
    , testCase "sign/verify P1363 round-trip" $ do
        Right kp <- generateKeyPair P521
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA512 "Hello, ECDSA P-521 P1363!"
        Right sig <- ecdsaSignP1363 kp digest
        Right valid <- ecdsaVerifyP1363 pub digest sig
        assertBool "P1363 signature should verify" valid
    , testCase "P1363 signature size is 132 bytes" $ do
        Right kp <- generateKeyPair P521
        let digest = hashSHA512 "test"
        Right sig <- ecdsaSignP1363 kp digest
        BS.length sig @?= 132
    , testCase "key serialization round-trip" $ do
        Right kp <- generateKeyPair P521
        Right pubBytes <- ecPublicKeyBytes kp
        Right privBytes <- ecPrivateKeyBytes kp
        Right kp2 <- ecKeyPairFromPrivateBytes P521 privBytes
        Right privBytes2 <- ecPrivateKeyBytes kp2
        privBytes2 @?= privBytes
        Right pub <- ecPublicKeyFromBytes P521 pubBytes
        let digest = hashSHA512 "round-trip test"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify with deserialized public key" valid
    ]
  ]
