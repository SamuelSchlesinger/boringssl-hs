{-# LANGUAGE OverloadedStrings #-}
module Test.Cipher (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Cipher

tests :: TestTree
tests = testGroup "Cipher"
  [ testGroup "AES-128-CBC"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "Hello, AES-CBC!!"  -- exactly 16 bytes
        Right ct <- encrypt AES128CBC key iv pt
        Right recovered <- decrypt AES128CBC key iv ct
        recovered @?= pt
    , testCase "NIST AES-128-CBC (F.2.1)" $ do
        -- NIST SP 800-38A F.2.1 CBC-AES128.Encrypt
        let Right key = Base16.decode "2b7e151628aed2a6abf7158809cf4f3c"
            Right iv  = Base16.decode "000102030405060708090a0b0c0d0e0f"
            Right pt  = Base16.decode "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            Right expectedCt = Base16.decode "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        Right ct <- encrypt AES128CBC key iv pt
        -- CBC adds padding, so ct will be longer than expectedCt
        -- We need to check that the first part matches (before padding block)
        BS.take (BS.length expectedCt) ct @?= expectedCt
    , testCase "bad padding detection" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            ct  = BS.replicate 16 0xFF  -- garbage
        result <- decrypt AES128CBC key iv ct
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on invalid padding"
    ]
  , testGroup "AES-256-CBC"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "Secret message for AES-256"
        Right ct <- encrypt AES256CBC key iv pt
        Right recovered <- decrypt AES256CBC key iv ct
        recovered @?= pt
    ]
  , testGroup "AES-128-CTR"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "CTR mode is a stream cipher"
        Right ct <- encrypt AES128CTR key iv pt
        Right recovered <- decrypt AES128CTR key iv ct
        recovered @?= pt
    , testCase "NIST AES-128-CTR (F.5.1)" $ do
        -- NIST SP 800-38A F.5.1 CTR-AES128.Encrypt
        let Right key = Base16.decode "2b7e151628aed2a6abf7158809cf4f3c"
            Right iv  = Base16.decode "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            Right pt  = Base16.decode "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            Right expectedCt = Base16.decode "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
        Right ct <- encrypt AES128CTR key iv pt
        ct @?= expectedCt
    ]
  , testGroup "AES-256-CTR"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "AES-256-CTR test"
        Right ct <- encrypt AES256CTR key iv pt
        Right recovered <- decrypt AES256CTR key iv ct
        recovered @?= pt
    ]
  , testGroup "Properties"
    [ testCase "key lengths" $ do
        cipherKeyLength AES128CBC @?= 16
        cipherKeyLength AES256CBC @?= 32
        cipherKeyLength AES128CTR @?= 16
        cipherKeyLength AES256CTR @?= 32
    , testCase "IV lengths" $ do
        cipherIVLength AES128CBC @?= 16
        cipherIVLength AES128CTR @?= 16
    , testCase "block sizes" $ do
        cipherBlockSize AES128CBC @?= 16
        cipherBlockSize AES256CBC @?= 16
        cipherBlockSize AES128CTR @?= 1
        cipherBlockSize AES256CTR @?= 1
    ]
  ]
