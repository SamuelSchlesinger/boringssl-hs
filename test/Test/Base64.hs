{-# LANGUAGE OverloadedStrings #-}
module Test.Base64 (tests) where

import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Base64

tests :: TestTree
tests = testGroup "Base64"
  [ testGroup "RFC 4648 test vectors"
    [ testCase "empty" $ encode "" @?= ""
    , testCase "f" $ encode "f" @?= "Zg=="
    , testCase "fo" $ encode "fo" @?= "Zm8="
    , testCase "foo" $ encode "foo" @?= "Zm9v"
    , testCase "foob" $ encode "foob" @?= "Zm9vYg=="
    , testCase "fooba" $ encode "fooba" @?= "Zm9vYmE="
    , testCase "foobar" $ encode "foobar" @?= "Zm9vYmFy"
    ]
  , testGroup "Round-trip"
    [ testCase "round-trip empty" $ decode (encode "") @?= Right ""
    , testCase "round-trip foobar" $ decode (encode "foobar") @?= Right "foobar"
    , testCase "round-trip binary" $ do
        let bs = BS8.pack ['\x00'..'\xFF']
        decode (encode bs) @?= Right bs
    ]
  , testGroup "Decode RFC 4648 vectors"
    [ testCase "empty" $ decode "" @?= Right ""
    , testCase "Zg==" $ decode "Zg==" @?= Right "f"
    , testCase "Zm8=" $ decode "Zm8=" @?= Right "fo"
    , testCase "Zm9v" $ decode "Zm9v" @?= Right "foo"
    , testCase "Zm9vYmFy" $ decode "Zm9vYmFy" @?= Right "foobar"
    ]
  , testGroup "Invalid input"
    [ testCase "invalid characters" $
        case decode "!!!!" of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on invalid base64"
    , testCase "truncated padding" $
        case decode "Zg=" of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on truncated padding"
    , testCase "single character" $
        case decode "Z" of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on single character"
    ]
  ]
