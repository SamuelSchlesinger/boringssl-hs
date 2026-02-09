{-# LANGUAGE OverloadedStrings #-}
module Test.MLDSA (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.MLDSA

tests :: TestTree
tests = testGroup "MLDSA"
  [ testGroup "ML-DSA-65"
    [ testCase "keygen produces correct public key size" $ do
        (pub, _priv) <- generateKeyPair
        BS.length pub @?= 1952

    , testCase "sign/verify round-trip" $ do
        (_pub, priv) <- generateKeyPair
        let msg = BS8.pack "Hello, post-quantum world!"
            ctx = BS.empty
        Just sig <- sign priv msg ctx
        BS.length sig @?= 3309
        let valid = verify priv sig msg ctx
        assertBool "signature should be valid" valid

    , testCase "sign/verify with context" $ do
        (_pub, priv) <- generateKeyPair
        let msg = BS8.pack "context test message"
            ctx = BS8.pack "my-application-context"
        Just sig <- sign priv msg ctx
        let valid = verify priv sig msg ctx
        assertBool "signature with context should be valid" valid

    , testCase "verify rejects invalid signature" $ do
        (_pub, priv) <- generateKeyPair
        let msg = BS8.pack "test message"
            ctx = BS.empty
        Just sig <- sign priv msg ctx
        -- Tamper with the signature
        let tampered = BS.cons (BS.head sig + 1) (BS.tail sig)
        let valid = verify priv tampered msg ctx
        assertBool "tampered signature should be invalid" (not valid)

    , testCase "verify rejects wrong message" $ do
        (_pub, priv) <- generateKeyPair
        let msg = BS8.pack "original message"
            ctx = BS.empty
        Just sig <- sign priv msg ctx
        let wrongMsg = BS8.pack "different message"
        let valid = verify priv sig wrongMsg ctx
        assertBool "wrong message should fail" (not valid)

    , testCase "verify rejects wrong context" $ do
        (_pub, priv) <- generateKeyPair
        let msg = BS8.pack "test"
            ctx1 = BS8.pack "context-a"
            ctx2 = BS8.pack "context-b"
        Just sig <- sign priv msg ctx1
        let valid = verify priv sig msg ctx2
        assertBool "wrong context should fail" (not valid)

    , testCase "different keys produce different signatures" $ do
        (_pub1, priv1) <- generateKeyPair
        (_pub2, priv2) <- generateKeyPair
        let msg = BS8.pack "shared message"
            ctx = BS.empty
        Just sig1 <- sign priv1 msg ctx
        Just sig2 <- sign priv2 msg ctx
        assertBool "different keys should produce different sigs" (sig1 /= sig2)
    ]
  ]
