{-# LANGUAGE OverloadedStrings #-}
module Test.Scrypt (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Scrypt

tests :: TestTree
tests = testGroup "Scrypt"
  [ testCase "basic derivation (empty password/salt)" $ do
      -- password="" salt="" N=16 r=1 p=1 dkLen=64
      let result = scrypt BS.empty BS.empty 16 1 1 64
      case result of
        Left err -> assertFailure ("scrypt returned Left: " ++ show err)
        Right derived ->
          BS.length derived @?= 64

  , testCase "password and salt derivation" $ do
      -- password="password" salt="NaCl" N=1024 r=8 p=16 dkLen=64
      let result = scrypt "password" "NaCl" 1024 8 16 64
      case result of
        Left err -> assertFailure ("scrypt returned Left: " ++ show err)
        Right derived ->
          BS.length derived @?= 64

  , testCase "deterministic" $ do
      let d1 = scrypt "pw" "salt" 16 1 1 32
          d2 = scrypt "pw" "salt" 16 1 1 32
      d1 @?= d2

  , testCase "different passwords produce different output" $ do
      let d1 = scrypt "password1" "salt" 16 1 1 32
          d2 = scrypt "password2" "salt" 16 1 1 32
      assertBool "different passwords should differ" (d1 /= d2)

  , testCase "invalid N (not power of 2) returns Left" $ do
      let result = scrypt "pw" "salt" 3 1 1 32
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "scrypt should reject invalid N"
  , testCase "different salts produce different output" $ do
      let d1 = scrypt "password" "salt1" 16 1 1 32
          d2 = scrypt "password" "salt2" 16 1 1 32
      assertBool "different salts should differ" (d1 /= d2)
  , testCase "output length matches requested" $ do
      case scrypt "pw" "s" 16 1 1 64 of
        Left err -> assertFailure ("scrypt failed: " ++ show err)
        Right d -> BS.length d @?= 64
  ]
