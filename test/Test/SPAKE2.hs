{-# LANGUAGE OverloadedStrings #-}
module Test.SPAKE2 (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.SPAKE2

tests :: TestTree
tests = testGroup "SPAKE2"
  [ testCase "Alice and Bob agree on key" $ do
      Right ctxA <- newContext Alice "alice" "bob"
      Right ctxB <- newContext Bob   "bob" "alice"
      let password = "shared password"
      Right msgA <- generateMessage ctxA password
      Right msgB <- generateMessage ctxB password
      Right keyA <- processMessage ctxA msgB
      Right keyB <- processMessage ctxB msgA
      keyA @?= keyB
  , testCase "different passwords produce different keys" $ do
      Right ctxA <- newContext Alice "alice" "bob"
      Right ctxB <- newContext Bob   "bob" "alice"
      Right msgA <- generateMessage ctxA "password1"
      Right msgB <- generateMessage ctxB "password2"
      Right keyA <- processMessage ctxA msgB
      Right keyB <- processMessage ctxB msgA
      assertBool "keys should differ with different passwords" (keyA /= keyB)
  , testCase "empty names work" $ do
      Right ctxA <- newContext Alice "" ""
      Right ctxB <- newContext Bob   "" ""
      let password = "test"
      Right msgA <- generateMessage ctxA password
      Right msgB <- generateMessage ctxB password
      Right keyA <- processMessage ctxA msgB
      Right keyB <- processMessage ctxB msgA
      keyA @?= keyB
  , testCase "invalid message rejected" $ do
      Right ctxA <- newContext Alice "a" "b"
      _ <- generateMessage ctxA "pw"
      result <- processMessage ctxA "invalid message that is clearly wrong"
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "should reject invalid message"
  ]
