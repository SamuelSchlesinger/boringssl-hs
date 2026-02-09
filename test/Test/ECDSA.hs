{-# LANGUAGE OverloadedStrings #-}
module Test.ECDSA (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (hashSHA256, hashSHA384)
import Crypto.BoringSSL.ECDSA

tests :: TestTree
tests = testGroup "ECDSA"
  [ testGroup "P-256"
    [ testCase "sign/verify round-trip" $ do
        kp <- generateKeyPair P256
        pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "Hello, ECDSA P-256!"
        Right sig <- ecdsaSign kp digest
        valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    , testCase "invalid signature rejected" $ do
        kp <- generateKeyPair P256
        pub <- ecPublicKeyOfPair kp
        let digest = hashSHA256 "Hello, ECDSA P-256!"
        Right sig <- ecdsaSign kp digest
        let badSig = BS.replicate (BS.length sig) 0x00
        valid <- ecdsaVerify pub digest badSig
        assertBool "bad signature should not verify" (not valid)
    , testCase "wrong digest rejected" $ do
        kp <- generateKeyPair P256
        pub <- ecPublicKeyOfPair kp
        let digest1 = hashSHA256 "message A"
            digest2 = hashSHA256 "message B"
        Right sig <- ecdsaSign kp digest1
        valid <- ecdsaVerify pub digest2 sig
        assertBool "wrong digest should not verify" (not valid)
    ]
  , testGroup "P-384"
    [ testCase "sign/verify round-trip" $ do
        kp <- generateKeyPair P384
        pub <- ecPublicKeyOfPair kp
        let digest = hashSHA384 "Hello, ECDSA P-384!"
        Right sig <- ecdsaSign kp digest
        valid <- ecdsaVerify pub digest sig
        assertBool "signature should verify" valid
    ]
  ]
