{-# LANGUAGE OverloadedStrings #-}
module Test.Digest (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest

tests :: TestTree
tests = testGroup "Digest"
  [ testGroup "SHA-256"
    [ testCase "empty string" $
        hexHash SHA256 BS.empty @?=
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    , testCase "abc" $
        hexHash SHA256 (BS8.pack "abc") @?=
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    , testCase "448-bit message" $
        hexHash SHA256 (BS8.pack "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") @?=
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    ]
  , testGroup "SHA-512"
    [ testCase "empty string" $
        hexHash SHA512 BS.empty @?=
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    , testCase "abc" $
        hexHash SHA512 (BS8.pack "abc") @?=
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    , testCase "448-bit message" $
        hexHash SHA512 (BS8.pack "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") @?=
          "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    ]
  , testGroup "hash function"
    [ testCase "hash SHA256 matches hashSHA256" $
        hash SHA256 (BS8.pack "test") @?= hashSHA256 (BS8.pack "test")
    , testCase "hash SHA512 matches hashSHA512" $
        hash SHA512 (BS8.pack "test") @?= hashSHA512 (BS8.pack "test")
    ]
  ]

hexHash :: Algorithm -> ByteString -> ByteString
hexHash algo = Base16.encode . hash algo
