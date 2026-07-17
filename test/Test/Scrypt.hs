{-# LANGUAGE OverloadedStrings #-}
module Test.Scrypt (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Error (CryptoError)
import Crypto.BoringSSL.Scrypt
import Crypto.BoringSSL.SecureBytes

hex :: BS.ByteString -> BS.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

tests :: TestTree
tests = testGroup "Scrypt"
  [ testCase "basic derivation (empty password/salt)" $ do
      -- password="" salt="" N=16 r=1 p=1 dkLen=64
      let result = scrypt BS.empty BS.empty (ScryptParams 16 1 1 0 64)
      case result of
        Left err -> assertFailure ("scrypt returned Left: " ++ show err)
        Right derived ->
          secureBytesLength derived @?= 64

  , testCase "password and salt derivation" $ do
      -- password="password" salt="NaCl" N=1024 r=8 p=16 dkLen=64
      let result = scrypt "password" "NaCl" (ScryptParams 1024 8 16 0 64)
      case result of
        Left err -> assertFailure ("scrypt returned Left: " ++ show err)
        Right derived ->
          secureBytesLength derived @?= 64

  , testCase "deterministic" $ do
      let d1 = fmap secureBytesToByteString $ scrypt "pw" "salt" (ScryptParams 16 1 1 0 32)
          d2 = fmap secureBytesToByteString $ scrypt "pw" "salt" (ScryptParams 16 1 1 0 32)
      d1 @?= d2

  , testCase "different passwords produce different output" $ do
      let d1 = fmap secureBytesToByteString $ scrypt "password1" "salt" (ScryptParams 16 1 1 0 32)
          d2 = fmap secureBytesToByteString $ scrypt "password2" "salt" (ScryptParams 16 1 1 0 32)
      assertBool "different passwords should differ" (d1 /= d2)

  , testCase "invalid N (not power of 2) returns Left" $ do
      let result = scrypt "pw" "salt" (ScryptParams 3 1 1 0 32)
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "scrypt should reject invalid N"
  , testCase "different salts produce different output" $ do
      let d1 = fmap secureBytesToByteString $ scrypt "password" "salt1" (ScryptParams 16 1 1 0 32)
          d2 = fmap secureBytesToByteString $ scrypt "password" "salt2" (ScryptParams 16 1 1 0 32)
      assertBool "different salts should differ" (d1 /= d2)
  , testCase "output length matches requested" $ do
      case scrypt "pw" "s" (ScryptParams 16 1 1 0 64) of
        Left err -> assertFailure ("scrypt failed: " ++ show err)
        Right d -> secureBytesLength d @?= 64
  , testGroup "RFC 7914 known-answer vectors"
    [ testCase "vector 1: empty password/salt N=16 r=1 p=1" $ do
        let expected = hex "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        case scrypt "" "" (ScryptParams 16 1 1 0 64) of
          Left err -> assertFailure ("scrypt failed: " ++ show err)
          Right derived ->
            secureBytesToByteString derived @?= expected
    , testCase "vector 2: password/NaCl N=1024 r=8 p=16" $ do
        let expected = hex "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        case scrypt "password" "NaCl" (ScryptParams 1024 8 16 0 64) of
          Left err -> assertFailure ("scrypt failed: " ++ show err)
          Right derived ->
            secureBytesToByteString derived @?= expected
    , testCase "vector 3: pleaseletmein/SodiumChloride N=16384 r=8 p=1" $ do
        let expected = hex "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
        case scrypt "pleaseletmein" "SodiumChloride" (ScryptParams 16384 8 1 0 64) of
          Left err -> assertFailure ("scrypt failed: " ++ show err)
          Right derived ->
            secureBytesToByteString derived @?= expected
    ]
  ]
