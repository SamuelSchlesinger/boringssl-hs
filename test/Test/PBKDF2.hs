{-# LANGUAGE OverloadedStrings #-}
module Test.PBKDF2 (tests) where

import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..))
import Crypto.BoringSSL.PBKDF2

unwrap :: Either CryptoError a -> a
unwrap (Right x) = x
unwrap (Left e)  = error ("unexpected error: " ++ show e)

tests :: TestTree
tests = testGroup "PBKDF2"
  [ testGroup "RFC 6070 (PBKDF2-HMAC-SHA1)"
    [ testCase "Test Vector 1 (1 iteration)" $ do
        let derived = unwrap $ pbkdf2 SHA1
              (BS8.pack "password") (BS8.pack "salt") 1 20
        Base16.encode (secureBytesToByteString derived) @?=
          "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    , testCase "Test Vector 2 (2 iterations)" $ do
        let derived = unwrap $ pbkdf2 SHA1
              (BS8.pack "password") (BS8.pack "salt") 2 20
        Base16.encode (secureBytesToByteString derived) @?=
          "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    , testCase "Test Vector 3 (4096 iterations)" $ do
        let derived = unwrap $ pbkdf2 SHA1
              (BS8.pack "password") (BS8.pack "salt") 4096 20
        Base16.encode (secureBytesToByteString derived) @?=
          "4b007901b765489abead49d926f721d065a429c1"
    , testCase "Test Vector 5 (4096 iterations, long password and salt)" $ do
        let derived = unwrap $ pbkdf2 SHA1
              (BS8.pack "passwordPASSWORDpassword")
              (BS8.pack "saltSALTsaltSALTsaltSALTsaltSALTsalt")
              4096 25
        Base16.encode (secureBytesToByteString derived) @?=
          "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    ]
  , testGroup "PBKDF2-HMAC-SHA256"
    [ testCase "basic round-trip" $ do
        let derived = unwrap $ pbkdf2 SHA256
              (BS8.pack "password") (BS8.pack "salt") 1 32
        -- Just verify it produces 32 bytes and doesn't crash
        secureBytesLength derived @?= 32
    , testCase "deterministic" $ do
        let d1 = fmap secureBytesToByteString $ pbkdf2 SHA256 (BS8.pack "pw") (BS8.pack "s") 100 32
            d2 = fmap secureBytesToByteString $ pbkdf2 SHA256 (BS8.pack "pw") (BS8.pack "s") 100 32
        d1 @?= d2
    , testCase "different passwords produce different output" $ do
        let d1 = fmap secureBytesToByteString $ pbkdf2 SHA256 "password1" "salt" 100 32
            d2 = fmap secureBytesToByteString $ pbkdf2 SHA256 "password2" "salt" 100 32
        assertBool "different passwords should differ" (d1 /= d2)
    , testCase "different salts produce different output" $ do
        let d1 = fmap secureBytesToByteString $ pbkdf2 SHA256 "password" "salt1" 100 32
            d2 = fmap secureBytesToByteString $ pbkdf2 SHA256 "password" "salt2" 100 32
        assertBool "different salts should differ" (d1 /= d2)
    , testCase "output length matches requested" $ do
        let d = unwrap $ pbkdf2 SHA256 "pw" "s" 100 64
        secureBytesLength d @?= 64
    ]
  ]
