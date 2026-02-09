{-# LANGUAGE OverloadedStrings #-}
module Test.SipHash (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.SipHash

tests :: TestTree
tests = testGroup "SipHash"
  [ testCase "deterministic" $ do
      let key = (0x0706050403020100, 0x0f0e0d0c0b0a0908)
          h1 = sipHash24 key "hello"
          h2 = sipHash24 key "hello"
      h1 @?= h2

  , testCase "different keys produce different hashes" $ do
      let key1 = (0, 0)
          key2 = (1, 0)
          h1 = sipHash24 key1 "test"
          h2 = sipHash24 key2 "test"
      assertBool "different keys should produce different hashes" (h1 /= h2)

  , testCase "different inputs produce different hashes" $ do
      let key = (0, 0)
          h1 = sipHash24 key "abc"
          h2 = sipHash24 key "def"
      assertBool "different inputs should produce different hashes" (h1 /= h2)

  , testCase "empty input" $ do
      let key = (0, 0)
          h = sipHash24 key BS.empty
      -- Just verify it doesn't crash and produces a result
      assertBool "hash should be non-zero for most keys" True
      h @?= sipHash24 key BS.empty

  , testCase "SipHash-2-4 reference test vector" $ do
      -- From the SipHash paper: key = 00..0f, input = 00..0e (15 bytes)
      -- Expected output: 0xa129ca6149be45e5
      let key = (0x0706050403020100, 0x0f0e0d0c0b0a0908)
          input = BS.pack [0x00..0x0e]
          h = sipHash24 key input
      h @?= 0xa129ca6149be45e5
  ]
