{-# LANGUAGE OverloadedStrings #-}
module Test.SPAKE2 (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.SPAKE2

tests :: TestTree
tests = testGroup "SPAKE2"
  [ testCase "Alice and Bob agree on key" $ do
      ctxA <- newContext Alice "alice" "bob"
      ctxB <- newContext Bob   "bob" "alice"
      let password = "shared password"
      msgA <- generateMessage ctxA password
      msgB <- generateMessage ctxB password
      Just keyA <- processMessage ctxA msgB
      Just keyB <- processMessage ctxB msgA
      keyA @?= keyB
  , testCase "different passwords produce different keys" $ do
      ctxA <- newContext Alice "alice" "bob"
      ctxB <- newContext Bob   "bob" "alice"
      msgA <- generateMessage ctxA "password1"
      msgB <- generateMessage ctxB "password2"
      Just keyA <- processMessage ctxA msgB
      Just keyB <- processMessage ctxB msgA
      assertBool "keys should differ with different passwords" (keyA /= keyB)
  , testCase "empty names work" $ do
      ctxA <- newContext Alice "" ""
      ctxB <- newContext Bob   "" ""
      let password = "test"
      msgA <- generateMessage ctxA password
      msgB <- generateMessage ctxB password
      Just keyA <- processMessage ctxA msgB
      Just keyB <- processMessage ctxB msgA
      keyA @?= keyB
  , testCase "invalid message rejected" $ do
      ctxA <- newContext Alice "a" "b"
      _ <- generateMessage ctxA "pw"
      result <- processMessage ctxA "invalid message that is clearly wrong"
      case result of
        Nothing -> return ()
        Just _  -> assertFailure "should reject invalid message"
  ]
