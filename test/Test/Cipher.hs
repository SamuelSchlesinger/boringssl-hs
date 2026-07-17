{-# LANGUAGE OverloadedStrings #-}
module Test.Cipher (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Cipher

hex :: BS.ByteString -> BS.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

tests :: TestTree
tests = testGroup "Cipher"
  [ testGroup "AES-128-CBC"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "Hello, AES-CBC!!"  -- exactly 16 bytes
        Right ct <- pure $ encrypt AES128CBC key iv pt
        Right recovered <- pure $ decrypt AES128CBC key iv ct
        recovered @?= pt
    , testCase "NIST AES-128-CBC (F.2.1)" $ do
        -- NIST SP 800-38A F.2.1 CBC-AES128.Encrypt
        let key = hex "2b7e151628aed2a6abf7158809cf4f3c"
            iv  = hex "000102030405060708090a0b0c0d0e0f"
            pt  = hex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            expectedCt = hex "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        Right ct <- pure $ encrypt AES128CBC key iv pt
        -- CBC adds padding, so ct will be longer than expectedCt
        -- We need to check that the first part matches (before padding block)
        BS.take (BS.length expectedCt) ct @?= expectedCt
    , testCase "bad padding detection" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            ct  = BS.replicate 16 0xFF  -- garbage
        result <- pure $ decrypt AES128CBC key iv ct
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should fail on invalid padding"
    ]
  , testGroup "AES-256-CBC"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "Secret message for AES-256"
        Right ct <- pure $ encrypt AES256CBC key iv pt
        Right recovered <- pure $ decrypt AES256CBC key iv ct
        recovered @?= pt
    ]
  , testGroup "AES-128-CTR"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "CTR mode is a stream cipher"
        Right ct <- pure $ encrypt AES128CTR key iv pt
        Right recovered <- pure $ decrypt AES128CTR key iv ct
        recovered @?= pt
    , testCase "NIST AES-128-CTR (F.5.1)" $ do
        -- NIST SP 800-38A F.5.1 CTR-AES128.Encrypt
        let key = hex "2b7e151628aed2a6abf7158809cf4f3c"
            iv  = hex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            pt  = hex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            expectedCt = hex "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
        Right ct <- pure $ encrypt AES128CTR key iv pt
        ct @?= expectedCt
    ]
  , testGroup "AES-256-CTR"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "AES-256-CTR test"
        Right ct <- pure $ encrypt AES256CTR key iv pt
        Right recovered <- pure $ decrypt AES256CTR key iv ct
        recovered @?= pt
    ]
  , testGroup "AES-128-ECB"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            pt  = BS8.pack "Hello, AES-ECB!!"  -- exactly 16 bytes
        Right ct <- pure $ encrypt AES128ECB key BS.empty pt
        Right recovered <- pure $ decrypt AES128ECB key BS.empty ct
        recovered @?= pt
    , testCase "non-block-aligned plaintext" $ do
        let key = BS.replicate 16 0x42
            pt  = BS8.pack "short"
        Right ct <- pure $ encrypt AES128ECB key BS.empty pt
        Right recovered <- pure $ decrypt AES128ECB key BS.empty ct
        recovered @?= pt
    ]
  , testGroup "AES-256-ECB"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            pt  = BS8.pack "AES-256-ECB test!"
        Right ct <- pure $ encrypt AES256ECB key BS.empty pt
        Right recovered <- pure $ decrypt AES256ECB key BS.empty ct
        recovered @?= pt
    ]
  , testGroup "AES-128-OFB"
    [ testCase "round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "OFB mode is a stream cipher"
        Right ct <- pure $ encrypt AES128OFB key iv pt
        Right recovered <- pure $ decrypt AES128OFB key iv ct
        recovered @?= pt
    , testCase "ciphertext length equals plaintext length" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "OFB no padding"
        Right ct <- pure $ encrypt AES128OFB key iv pt
        BS.length ct @?= BS.length pt
    ]
  , testGroup "AES-256-OFB"
    [ testCase "round-trip" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "AES-256-OFB test!"
        Right ct <- pure $ encrypt AES256OFB key iv pt
        Right recovered <- pure $ decrypt AES256OFB key iv ct
        recovered @?= pt
    ]
  , testGroup "Properties"
    [ testCase "key lengths" $ do
        cipherKeyLength AES128CBC @?= 16
        cipherKeyLength AES256CBC @?= 32
        cipherKeyLength AES128CTR @?= 16
        cipherKeyLength AES256CTR @?= 32
        cipherKeyLength AES128ECB @?= 16
        cipherKeyLength AES256ECB @?= 32
        cipherKeyLength AES128OFB @?= 16
        cipherKeyLength AES256OFB @?= 32
    , testCase "IV lengths" $ do
        cipherIVLength AES128CBC @?= 16
        cipherIVLength AES128CTR @?= 16
        cipherIVLength AES128ECB @?= 0
        cipherIVLength AES256ECB @?= 0
        cipherIVLength AES128OFB @?= 16
        cipherIVLength AES256OFB @?= 16
    , testCase "block sizes" $ do
        cipherBlockSize AES128CBC @?= 16
        cipherBlockSize AES256CBC @?= 16
        cipherBlockSize AES128CTR @?= 1
        cipherBlockSize AES256CTR @?= 1
        cipherBlockSize AES128ECB @?= 16
        cipherBlockSize AES256ECB @?= 16
        cipherBlockSize AES128OFB @?= 1
        cipherBlockSize AES256OFB @?= 1
    ]
  , testGroup "stream cipher length"
    [ testCase "CTR ciphertext length equals plaintext" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "arbitrary length text"
        Right ct <- pure $ encrypt AES128CTR key iv pt
        BS.length ct @?= BS.length pt
    , testCase "OFB ciphertext length equals plaintext" $ do
        let key = BS.replicate 32 0x42
            iv  = BS.replicate 16 0x01
            pt  = BS8.pack "arbitrary length text"
        Right ct <- pure $ encrypt AES256OFB key iv pt
        BS.length ct @?= BS.length pt
    ]
  , testGroup "empty plaintext"
    [ testCase "CBC empty plaintext round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
        Right ct <- pure $ encrypt AES128CBC key iv BS.empty
        Right recovered <- pure $ decrypt AES128CBC key iv ct
        recovered @?= BS.empty
    , testCase "CTR empty plaintext round-trip" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 16 0x01
        Right ct <- pure $ encrypt AES128CTR key iv BS.empty
        BS.length ct @?= 0
    ]
  , testGroup "different IV produces different ciphertext"
    [ testCase "AES-128-CBC" $ do
        let key = BS.replicate 16 0x42
            iv1 = BS.replicate 16 0x01
            iv2 = BS.replicate 16 0x02
            pt  = BS8.pack "Hello, AES-CBC!!"
        Right ct1 <- pure $ encrypt AES128CBC key iv1 pt
        Right ct2 <- pure $ encrypt AES128CBC key iv2 pt
        assertBool "different IVs should produce different ciphertexts" (ct1 /= ct2)
    ]
  , testGroup "Input validation"
    [ testCase "encrypt rejects wrong key length" $ do
        let key = BS.replicate 15 0x42  -- should be 16 for AES-128
            iv  = BS.replicate 16 0x01
            pt  = "test"
        result <- pure $ encrypt AES128CBC key iv pt
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject wrong key length"
    , testCase "encrypt rejects wrong IV length" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 15 0x01  -- should be 16
            pt  = "test"
        result <- pure $ encrypt AES128CBC key iv pt
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject wrong IV length"
    , testCase "decrypt rejects wrong key length" $ do
        let key = BS.replicate 15 0x42  -- should be 16 for AES-128
            iv  = BS.replicate 16 0x01
            ct  = BS.replicate 16 0xFF
        result <- pure $ decrypt AES128CBC key iv ct
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject wrong key length"
    , testCase "decrypt rejects wrong IV length" $ do
        let key = BS.replicate 16 0x42
            iv  = BS.replicate 15 0x01  -- should be 16
            ct  = BS.replicate 16 0xFF
        result <- pure $ decrypt AES128CBC key iv ct
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject wrong IV length"
    , testCase "AES-256 rejects 16-byte key" $ do
        let key = BS.replicate 16 0x42  -- should be 32 for AES-256
            iv  = BS.replicate 16 0x01
            pt  = "test"
        result <- pure $ encrypt AES256CBC key iv pt
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "AES-256 should reject 16-byte key"
    , testCase "AES-128 rejects 32-byte key" $ do
        let key = BS.replicate 32 0x42  -- should be 16 for AES-128
            iv  = BS.replicate 16 0x01
            pt  = "test"
        result <- pure $ encrypt AES128CBC key iv pt
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "AES-128 should reject 32-byte key"
    ]
  ]
