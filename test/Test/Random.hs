{-# LANGUAGE OverloadedStrings #-}
module Test.Random (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Random

tests :: TestTree
tests = testGroup "Random"
  [ testCase "correct length" $ do
      bs <- randomBytes 32
      BS.length bs @?= 32
  , testCase "correct length (0)" $ do
      bs <- randomBytes 0
      BS.length bs @?= 0
  , testCase "correct length (1024)" $ do
      bs <- randomBytes 1024
      BS.length bs @?= 1024
  , testCase "two calls produce different output" $ do
      a <- randomBytes 32
      b <- randomBytes 32
      assertBool "random bytes should differ" (a /= b)
  , testCase "negative input returns empty" $ do
      bs <- randomBytes (-1)
      BS.length bs @?= 0
  , testCase "not all zeros (entropy sanity)" $ do
      bs <- randomBytes 256
      assertBool "256 random bytes should not be all zeros" (bs /= BS.replicate 256 0)
  ]
