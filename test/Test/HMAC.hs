{-# LANGUAGE OverloadedStrings #-}
module Test.HMAC (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..), digestSize)
import Crypto.BoringSSL.Error (CryptoError)
import Crypto.BoringSSL.HMAC

-- | Extract Right or fail the test (streaming API).
unwrap :: Either CryptoError a -> IO a
unwrap (Right x) = return x
unwrap (Left err) = assertFailure ("unexpected error: " ++ show err) >> error "unreachable"

tests :: TestTree
tests = testGroup "HMAC"
  [ testGroup "RFC 4231 test vectors"
    [ testCase "Test Case 1 (HMAC-SHA-256)" $ do
        -- Key = 0x0b repeated 20 times, Data = "Hi There"
        let key = BS.replicate 20 0x0b
        Base16.encode (hmac SHA256 key "Hi There") @?=
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    , testCase "Test Case 2 (HMAC-SHA-256)" $
        Base16.encode (hmac SHA256 "Jefe" "what do ya want for nothing?") @?=
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    , testCase "Test Case 1 (HMAC-SHA-512)" $ do
        let key = BS.replicate 20 0x0b
        Base16.encode (hmac SHA512 key "Hi There") @?=
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    , testCase "Test Case 3 (HMAC-SHA-256) - key=0xaa repeated 20" $ do
        -- Key = 0xaa repeated 20 times, Data = 0xdd repeated 50 times
        let key = BS.replicate 20 0xaa
            msg = BS.replicate 50 0xdd
        Base16.encode (hmac SHA256 key msg) @?=
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    , testCase "Test Case 1 (HMAC-SHA-384)" $ do
        let key = BS.replicate 20 0x0b
        Base16.encode (hmac SHA384 key "Hi There") @?=
          "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    , testCase "Test Case 1 (HMAC-SHA-1)" $ do
        let key = BS.replicate 20 0x0b
        Base16.encode (hmac SHA1 key "Hi There") @?=
          "b617318655057264e28bc0b6fb378c8ef146be00"
    ]
  , testGroup "Streaming"
    [ testCase "streaming matches one-shot" $ do
        let key = BS.replicate 20 0x0b
        ctx <- unwrap =<< hmacInit SHA256 key
        unwrap =<< hmacUpdate ctx "Hi There"
        result <- unwrap =<< hmacFinalize ctx
        result @?= hmac SHA256 key "Hi There"
    , testCase "streaming multiple updates" $ do
        let key = "Jefe"
        ctx <- unwrap =<< hmacInit SHA256 key
        unwrap =<< hmacUpdate ctx "what do ya "
        unwrap =<< hmacUpdate ctx "want for nothing?"
        result <- unwrap =<< hmacFinalize ctx
        result @?= hmac SHA256 key "what do ya want for nothing?"
    , testCase "SHA-512 streaming matches one-shot" $ do
        let key = BS.replicate 20 0x0b
        ctx <- unwrap =<< hmacInit SHA512 key
        unwrap =<< hmacUpdate ctx "Hi There"
        result <- unwrap =<< hmacFinalize ctx
        result @?= hmac SHA512 key "Hi There"
    , testCase "SHA-384 streaming matches one-shot" $ do
        let key = BS.replicate 20 0x0b
        ctx <- unwrap =<< hmacInit SHA384 key
        unwrap =<< hmacUpdate ctx "Hi There"
        result <- unwrap =<< hmacFinalize ctx
        result @?= hmac SHA384 key "Hi There"
    , testCase "streaming with empty update" $ do
        let key = BS.replicate 20 0x0b
        ctx <- unwrap =<< hmacInit SHA256 key
        unwrap =<< hmacUpdate ctx BS.empty
        unwrap =<< hmacUpdate ctx "Hi There"
        unwrap =<< hmacUpdate ctx BS.empty
        result <- unwrap =<< hmacFinalize ctx
        result @?= hmac SHA256 key "Hi There"
    ]
  , testGroup "hmacVerify"
    [ testCase "correct MAC verifies" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
        assertBool "correct MAC should verify" (hmacVerify SHA256 key msg (hmac SHA256 key msg))
    , testCase "wrong MAC rejects" $ do
        let key = BS.replicate 20 0x0b
            badMac = BS.replicate 32 0x00
        assertBool "wrong MAC should not verify" (not (hmacVerify SHA256 key "Hi There" badMac))
    , testCase "wrong key rejects" $ do
        let key1 = BS.replicate 20 0x0b
            key2 = BS.replicate 20 0x0c
            msg = "Hi There"
        assertBool "wrong key should not verify" (not (hmacVerify SHA256 key2 msg (hmac SHA256 key1 msg)))
    , testCase "wrong message rejects" $ do
        let key = BS.replicate 20 0x0b
            msg = "Hi There"
        assertBool "wrong message should not verify" (not (hmacVerify SHA256 key "Bye There" (hmac SHA256 key msg)))
    , testCase "wrong-length expected MAC rejects" $ do
        let key = BS.replicate 20 0x0b
        assertBool "truncated MAC should not verify"
          (not (hmacVerify SHA256 key "Hi There" (BS.take 16 (hmac SHA256 key "Hi There"))))
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
  , testGroup "edge cases"
    [ testCase "empty key" $
        BS.length (hmac SHA256 BS.empty "message") @?= digestSize SHA256
    , testCase "empty message" $
        BS.length (hmac SHA256 "key" BS.empty) @?= digestSize SHA256
    , testCase "empty key and message" $
        BS.length (hmac SHA256 BS.empty BS.empty) @?= digestSize SHA256
    ]
  , testGroup "output length"
    [ testCase "SHA-1 output = 20" $ BS.length (hmac SHA1 "k" "m") @?= digestSize SHA1
    , testCase "SHA-224 output = 28" $ BS.length (hmac SHA224 "k" "m") @?= digestSize SHA224
    , testCase "SHA-256 output = 32" $ BS.length (hmac SHA256 "k" "m") @?= digestSize SHA256
    , testCase "SHA-384 output = 48" $ BS.length (hmac SHA384 "k" "m") @?= digestSize SHA384
    , testCase "SHA-512 output = 64" $ BS.length (hmac SHA512 "k" "m") @?= digestSize SHA512
    , testCase "SHA-512/256 output = 32" $ BS.length (hmac SHA512_256 "k" "m") @?= digestSize SHA512_256
    , testCase "MD5 output = 16" $ BS.length (hmac MD5 "k" "m") @?= digestSize MD5
    , testCase "BLAKE2b-256 output = 32" $ BS.length (hmac BLAKE2b256 "k" "m") @?= digestSize BLAKE2b256
    ]
  ]
