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
  , testGroup "SHA-1"
    [ testCase "empty string" $
        hexHash SHA1 BS.empty @?=
          "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    , testCase "abc" $
        hexHash SHA1 (BS8.pack "abc") @?=
          "a9993e364706816aba3e25717850c26c9cd0d89d"
    ]
  , testGroup "SHA-224"
    [ testCase "abc" $
        hexHash SHA224 (BS8.pack "abc") @?=
          "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    ]
  , testGroup "SHA-384"
    [ testCase "abc" $
        hexHash SHA384 (BS8.pack "abc") @?=
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    ]
  , testGroup "SHA-512/256"
    [ testCase "empty string" $
        hexHash SHA512_256 BS.empty @?=
          "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    ]
  , testGroup "MD5"
    [ testCase "empty string" $
        hexHash MD5 BS.empty @?=
          "d41d8cd98f00b204e9800998ecf8427e"
    , testCase "abc" $
        hexHash MD5 (BS8.pack "abc") @?=
          "900150983cd24fb0d6963f7d28e17f72"
    ]
  , testGroup "hash function"
    [ testCase "hash SHA256 matches hashSHA256" $
        hash SHA256 (BS8.pack "test") @?= hashSHA256 (BS8.pack "test")
    , testCase "hash SHA512 matches hashSHA512" $
        hash SHA512 (BS8.pack "test") @?= hashSHA512 (BS8.pack "test")
    , testCase "hash SHA1 matches hashSHA1" $
        hash SHA1 (BS8.pack "test") @?= hashSHA1 (BS8.pack "test")
    , testCase "hash MD5 matches hashMD5" $
        hash MD5 (BS8.pack "test") @?= hashMD5 (BS8.pack "test")
    ]
  , testGroup "Streaming"
    [ testCase "SHA-256 streaming matches one-shot" $ do
        ctx <- digestInit SHA256
        digestUpdate ctx (BS8.pack "abc")
        result <- digestFinalize ctx
        result @?= hash SHA256 (BS8.pack "abc")
    , testCase "SHA-256 streaming multiple updates" $ do
        ctx <- digestInit SHA256
        digestUpdate ctx (BS8.pack "ab")
        digestUpdate ctx (BS8.pack "c")
        result <- digestFinalize ctx
        result @?= hash SHA256 (BS8.pack "abc")
    , testCase "SHA-512 streaming matches one-shot" $ do
        ctx <- digestInit SHA512
        digestUpdate ctx (BS8.pack "abc")
        result <- digestFinalize ctx
        result @?= hash SHA512 (BS8.pack "abc")
    , testCase "MD5 streaming matches one-shot" $ do
        ctx <- digestInit MD5
        digestUpdate ctx (BS8.pack "abc")
        result <- digestFinalize ctx
        result @?= hash MD5 (BS8.pack "abc")
    ]
  , testGroup "digestSize"
    [ testCase "SHA-1 = 20" $ digestSize SHA1 @?= 20
    , testCase "SHA-224 = 28" $ digestSize SHA224 @?= 28
    , testCase "SHA-256 = 32" $ digestSize SHA256 @?= 32
    , testCase "SHA-384 = 48" $ digestSize SHA384 @?= 48
    , testCase "SHA-512 = 64" $ digestSize SHA512 @?= 64
    , testCase "SHA-512/256 = 32" $ digestSize SHA512_256 @?= 32
    , testCase "MD5 = 16" $ digestSize MD5 @?= 16
    ]
  ]

hexHash :: Algorithm -> ByteString -> ByteString
hexHash algo = Base16.encode . hash algo
