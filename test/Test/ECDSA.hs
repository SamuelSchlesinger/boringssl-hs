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
        pubBytes <- ecPublicKeyBytes kp
        privBytes <- ecPrivateKeyBytes kp
        -- Round-trip private key
        Right kp2 <- ecKeyPairFromPrivateBytes P256 privBytes
        privBytes2 <- ecPrivateKeyBytes kp2
        privBytes2 @?= privBytes
        -- Round-trip public key
        Right pub <- ecPublicKeyFromBytes P256 pubBytes
        let digest = hashSHA256 "round-trip test"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature from original key should verify with deserialized public key" valid
    ]
  , testGroup "P-384"
    [ testCase "sign/verify round-trip" $ do
        Right kp <- generateKeyPair P384
        Right pub <- ecPublicKeyOfPair kp
        let digest = hashSHA384 "Hello, ECDSA P-384!"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    , testCase "key serialization round-trip" $ do
        Right kp <- generateKeyPair P384
        pubBytes <- ecPublicKeyBytes kp
        privBytes <- ecPrivateKeyBytes kp
        Right kp2 <- ecKeyPairFromPrivateBytes P384 privBytes
        privBytes2 <- ecPrivateKeyBytes kp2
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
    , testCase "key serialization round-trip" $ do
        Right kp <- generateKeyPair P521
        pubBytes <- ecPublicKeyBytes kp
        privBytes <- ecPrivateKeyBytes kp
        Right kp2 <- ecKeyPairFromPrivateBytes P521 privBytes
        privBytes2 <- ecPrivateKeyBytes kp2
        privBytes2 @?= privBytes
        Right pub <- ecPublicKeyFromBytes P521 pubBytes
        let digest = hashSHA512 "round-trip test"
        Right sig <- ecdsaSign kp digest
        Right valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify with deserialized public key" valid
    ]
  ]
