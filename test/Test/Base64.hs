{-# LANGUAGE OverloadedStrings #-}
module Test.Base64 (tests) where

import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Base64

tests :: TestTree
tests = testGroup "Base64"
  [ testGroup "RFC 4648 test vectors"
    [ testCase "empty" $ encode "" @?= Right ""
    , testCase "f" $ encode "f" @?= Right "Zg=="
    , testCase "fo" $ encode "fo" @?= Right "Zm8="
    , testCase "foo" $ encode "foo" @?= Right "Zm9v"
    , testCase "foob" $ encode "foob" @?= Right "Zm9vYg=="
    , testCase "fooba" $ encode "fooba" @?= Right "Zm9vYmE="
    , testCase "foobar" $ encode "foobar" @?= Right "Zm9vYmFy"
    ]
  , testGroup "Round-trip"
    [ testCase "round-trip empty" $ do
        Right enc <- return $ encode ""
        decode enc @?= Right ""
    , testCase "round-trip foobar" $ do
        Right enc <- return $ encode "foobar"
        decode enc @?= Right "foobar"
    , testCase "round-trip binary" $ do
        let bs = BS8.pack ['\x00'..'\xFF']
        Right enc <- return $ encode bs
        decode enc @?= Right bs
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
