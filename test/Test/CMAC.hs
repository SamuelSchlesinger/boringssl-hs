{-# LANGUAGE OverloadedStrings #-}
module Test.CMAC (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.CMAC

hex :: BS8.ByteString -> BS8.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error $ "bad hex literal: " ++ err

tests :: TestTree
tests = testGroup "CMAC"
  [ testGroup "One-shot"
    [ testCase "AES-128 produces 16-byte tag" $ do
        let key = BS.replicate 16 0
            tag = cmac key "test message"
        BS.length tag @?= 16

    , testCase "AES-256 produces 16-byte tag" $ do
        let key = BS.replicate 32 0
            tag = cmac key "test message"
        BS.length tag @?= 16

    , testCase "deterministic" $ do
        let key = BS8.pack "0123456789abcdef"
            msg = "hello"
        cmac key msg @?= cmac key msg

    , testCase "different keys produce different tags" $ do
        let key1 = BS.replicate 16 0
            key2 = BS.replicate 16 1
            msg  = "test"
        assertBool "different keys should produce different tags"
          (cmac key1 msg /= cmac key2 msg)

    , testCase "different messages produce different tags" $ do
        let key  = BS.replicate 16 0
        assertBool "different messages should produce different tags"
          (cmac key "message1" /= cmac key "message2")

    , testCase "empty message" $ do
        let key = BS.replicate 16 0
            tag = cmac key BS.empty
        BS.length tag @?= 16

    , testCase "RFC 4493 test vector 1 (empty message)" $ do
        let key = hex $ "2b7e151628aed2a6abf7158809cf4f3c"
            tag = cmac key BS.empty
        Base16.encode tag @?= "bb1d6929e95937287fa37d129b756746"

    , testCase "RFC 4493 test vector 3 (40 bytes)" $ do
        let key = hex $ "2b7e151628aed2a6abf7158809cf4f3c"
            msg = hex $
                    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
            tag = cmac key msg
        Base16.encode tag @?= "dfa66747de9ae63030ca32611497c827"

    , testCase "RFC 4493 test vector 4 (64 bytes)" $ do
        let key = hex $ "2b7e151628aed2a6abf7158809cf4f3c"
            msg = hex $
                    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            tag = cmac key msg
        Base16.encode tag @?= "51f0bebf7e3b9d92fc49741779363cfe"
    ]
  , testGroup "Incremental"
    [ testCase "matches one-shot" $ do
        let key = BS8.pack "0123456789abcdef"
            msg = "hello, streaming CMAC!"
            oneShot = cmac key msg
        Right ctx <- cmacInit key
        Right () <- cmacUpdate ctx msg
        Right streamed <- cmacFinalize ctx
        streamed @?= oneShot

    , testCase "multiple updates match one-shot" $ do
        let key = BS.replicate 16 42
            part1 = "first "
            part2 = "second "
            part3 = "third"
            oneShot = cmac key (BS.concat [part1, part2, part3])
        Right ctx <- cmacInit key
        Right () <- cmacUpdate ctx part1
        Right () <- cmacUpdate ctx part2
        Right () <- cmacUpdate ctx part3
        Right streamed <- cmacFinalize ctx
        streamed @?= oneShot

    , testCase "AES-256 incremental" $ do
        let key = BS.replicate 32 0
            msg = "test 256"
            oneShot = cmac key msg
        Right ctx <- cmacInit key
        Right () <- cmacUpdate ctx msg
        Right streamed <- cmacFinalize ctx
        streamed @?= oneShot
    ]
  ]
