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
  , testGroup "Invalid input"
    [ testCase "invalid characters" $
        case decode "!!!!" of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on invalid base64"
    ]
  ]
