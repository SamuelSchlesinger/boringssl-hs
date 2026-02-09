{-# LANGUAGE OverloadedStrings #-}
module Test.HKDF (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..))
import Crypto.BoringSSL.HKDF

tests :: TestTree
tests = testGroup "HKDF"
  [ testGroup "RFC 5869 Appendix A"
    [ testCase "Test Case 1 (SHA-256)" $ do
        -- IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        -- salt = 0x000102030405060708090a0b0c (13 octets)
        -- info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
        -- L = 42
        let Right ikm  = Base16.decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
            Right salt = Base16.decode "000102030405060708090a0b0c"
            Right info = Base16.decode "f0f1f2f3f4f5f6f7f8f9"
            Right expectedPRK = Base16.decode "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
            Right expectedOKM = Base16.decode "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        -- Test extract
        Base16.encode (hkdfExtract SHA256 ikm salt) @?= Base16.encode expectedPRK
        -- Test expand
        let prk = hkdfExtract SHA256 ikm salt
        Base16.encode (hkdfExpand SHA256 prk info 42) @?= Base16.encode expectedOKM
        -- Test full hkdf
        Base16.encode (hkdf SHA256 ikm salt info 42) @?= Base16.encode expectedOKM
    , testCase "Test Case 2 (SHA-256)" $ do
        let Right ikm  = Base16.decode "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
            Right salt = Base16.decode "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            Right info = Base16.decode "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            Right expectedOKM = Base16.decode "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        Base16.encode (hkdf SHA256 ikm salt info 82) @?= Base16.encode expectedOKM
    , testCase "Test Case 3 (SHA-256, empty salt and info)" $ do
        let Right ikm = Base16.decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
            salt = BS.empty
            info = BS.empty
            Right expectedOKM = Base16.decode "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        Base16.encode (hkdf SHA256 ikm salt info 42) @?= Base16.encode expectedOKM
    ]
  ]
