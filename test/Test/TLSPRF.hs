{-# LANGUAGE OverloadedStrings #-}
module Test.TLSPRF (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..))
import Crypto.BoringSSL.TLSPRF

tests :: TestTree
tests = testGroup "TLSPRF"
  [ testCase "produces requested output length" $ do
      let result = tlsPRF SHA256 32 "secret" "label" "seed1" "seed2"
      case result of
        Left err -> assertFailure ("tlsPRF returned Left: " ++ show err)
        Right derived -> BS.length derived @?= 32

  , testCase "deterministic" $ do
      let d1 = tlsPRF SHA256 48 "secret" "label" "seed1" "seed2"
          d2 = tlsPRF SHA256 48 "secret" "label" "seed1" "seed2"
      d1 @?= d2

  , testCase "different secrets produce different output" $ do
      let d1 = tlsPRF SHA256 32 "secret1" "label" "seed" ""
          d2 = tlsPRF SHA256 32 "secret2" "label" "seed" ""
      assertBool "different secrets should differ" (d1 /= d2)

  , testCase "different labels produce different output" $ do
      let d1 = tlsPRF SHA256 32 "secret" "label1" "seed" ""
          d2 = tlsPRF SHA256 32 "secret" "label2" "seed" ""
      assertBool "different labels should differ" (d1 /= d2)

  , testCase "different algorithms produce different output" $ do
      let d1 = tlsPRF SHA256 32 "secret" "label" "seed" ""
          d2 = tlsPRF SHA384 32 "secret" "label" "seed" ""
      assertBool "different algorithms should differ" (d1 /= d2)

  , testCase "SHA-384 works" $ do
      let result = tlsPRF SHA384 64 "master secret" "key expansion" "server_random" "client_random"
      case result of
        Left err -> assertFailure ("tlsPRF with SHA384 returned Left: " ++ show err)
        Right derived -> BS.length derived @?= 64

  , testCase "empty seed2 works" $ do
      let result = tlsPRF SHA256 32 "secret" "label" "seed1" BS.empty
      case result of
        Left err -> assertFailure ("tlsPRF with empty seed2 returned Left: " ++ show err)
        Right derived -> BS.length derived @?= 32
  ]
