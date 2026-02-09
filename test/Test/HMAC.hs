{-# LANGUAGE OverloadedStrings #-}
module Test.HMAC (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..))
import Crypto.BoringSSL.HMAC

tests :: TestTree
tests = testGroup "HMAC"
  [ testGroup "RFC 4231 test vectors"
    [ testCase "Test Case 1 (HMAC-SHA-256)" $ do
        -- Key = 0x0b repeated 20 times, Data = "Hi There"
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
        Base16.encode (hmac SHA256 key msg) @?=
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    , testCase "Test Case 2 (HMAC-SHA-256)" $ do
        -- Key = "Jefe", Data = "what do ya want for nothing?"
        let key = "Jefe"
            msg = "what do ya want for nothing?"
        Base16.encode (hmac SHA256 key msg) @?=
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    , testCase "Test Case 1 (HMAC-SHA-512)" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
        Base16.encode (hmac SHA512 key msg) @?=
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    ]
  , testGroup "Streaming"
    [ testCase "streaming matches one-shot" $ do
        let key = BS.replicate 20 0x0b
        ctx <- hmacInit SHA256 key
        hmacUpdate ctx "Hi There"
        result <- hmacFinalize ctx
        result @?= hmac SHA256 key "Hi There"
    , testCase "streaming multiple updates" $ do
        let key = "Jefe"
        ctx <- hmacInit SHA256 key
        hmacUpdate ctx "what do ya "
        hmacUpdate ctx "want for nothing?"
        result <- hmacFinalize ctx
        result @?= hmac SHA256 key "what do ya want for nothing?"
    ]
  , testGroup "hmacVerify"
    [ testCase "correct MAC verifies" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
            mac = hmac SHA256 key msg
        assertBool "correct MAC should verify" (hmacVerify SHA256 key msg mac)
    , testCase "wrong MAC rejects" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
            badMac = BS.replicate 32 0x00
        assertBool "wrong MAC should not verify" (not (hmacVerify SHA256 key msg badMac))
    , testCase "wrong key rejects" $ do
        let key1 = BS.replicate 20 0x0b
            key2 = BS.replicate 20 0x0c
            msg = "Hi There"
            mac = hmac SHA256 key1 msg
        assertBool "wrong key should not verify" (not (hmacVerify SHA256 key2 msg mac))
    , testCase "wrong message rejects" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
            mac = hmac SHA256 key msg
        assertBool "wrong message should not verify" (not (hmacVerify SHA256 key "Bye There" mac))
    ]
  , testGroup "constTimeEq"
    [ testCase "equal ByteStrings" $ do
        let bs = "hello world"
        assertBool "same value should be equal" (constTimeEq bs bs)
    , testCase "equal but distinct ByteStrings" $ do
        let a = BS.pack [1,2,3,4,5]
            b = BS.pack [1,2,3,4,5]
        assertBool "equal values should be equal" (constTimeEq a b)
    , testCase "different ByteStrings same length" $ do
        let a = BS.pack [1,2,3,4,5]
            b = BS.pack [1,2,3,4,6]
        assertBool "different values should not be equal" (not (constTimeEq a b))
    , testCase "different lengths" $ do
        let a = BS.pack [1,2,3]
            b = BS.pack [1,2,3,4]
        assertBool "different lengths should not be equal" (not (constTimeEq a b))
    , testCase "empty ByteStrings" $ do
        assertBool "two empty should be equal" (constTimeEq BS.empty BS.empty)
    ]
  ]
