{-# LANGUAGE OverloadedStrings #-}
module Test.HKDF (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Digest (Algorithm(..), digestSize)
import Crypto.BoringSSL.HKDF

hex :: BS.ByteString -> BS.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

unwrap :: Either CryptoError a -> a
unwrap (Right x) = x
unwrap (Left e)  = error ("unexpected error: " ++ show e)

tests :: TestTree
tests = testGroup "HKDF"
  [ testGroup "RFC 5869 Appendix A"
    [ testCase "Test Case 1 (SHA-256)" $ do
        let ikm  = hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
            salt = hex "000102030405060708090a0b0c"
            info = hex "f0f1f2f3f4f5f6f7f8f9"
            expectedPRK = hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
            expectedOKM = hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        -- Test extract
        let prk = unwrap $ hkdfExtract SHA256 ikm salt
        Base16.encode (secureBytesToByteString prk) @?= Base16.encode expectedPRK
        -- Test expand
        let okm = unwrap $ hkdfExpand SHA256 (secureBytesToByteString prk) info 42
        Base16.encode (secureBytesToByteString okm) @?= Base16.encode expectedOKM
        -- Test full hkdf
        let fullOkm = unwrap $ hkdf SHA256 ikm salt info 42
        Base16.encode (secureBytesToByteString fullOkm) @?= Base16.encode expectedOKM
    , testCase "Test Case 2 (SHA-256)" $ do
        let ikm  = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
            salt = hex "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            info = hex "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            expectedOKM = hex "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        Base16.encode (secureBytesToByteString (unwrap $ hkdf SHA256 ikm salt info 82)) @?= Base16.encode expectedOKM
    , testCase "Test Case 3 (SHA-256, empty salt and info)" $ do
        let ikm = hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
            salt = BS.empty
            info = BS.empty
            expectedOKM = hex "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        Base16.encode (secureBytesToByteString (unwrap $ hkdf SHA256 ikm salt info 42)) @?= Base16.encode expectedOKM
    , testCase "Test Case 4 (SHA-1)" $ do
        let ikm  = hex "0b0b0b0b0b0b0b0b0b0b0b"
            salt = hex "000102030405060708090a0b0c"
            info = hex "f0f1f2f3f4f5f6f7f8f9"
            expectedPRK = hex "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"
            expectedOKM = hex "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
        let prk = unwrap $ hkdfExtract SHA1 ikm salt
        Base16.encode (secureBytesToByteString prk) @?= Base16.encode expectedPRK
        let okm = unwrap $ hkdfExpand SHA1 (secureBytesToByteString prk) info 42
        Base16.encode (secureBytesToByteString okm) @?= Base16.encode expectedOKM
        Base16.encode (secureBytesToByteString (unwrap $ hkdf SHA1 ikm salt info 42)) @?= Base16.encode expectedOKM
    , testCase "Test Case 7 (SHA-1, empty salt and info)" $ do
        let ikm  = hex "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
            salt = BS.empty
            info = BS.empty
            expectedOKM = hex "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"
        Base16.encode (secureBytesToByteString (unwrap $ hkdf SHA1 ikm salt info 42)) @?= Base16.encode expectedOKM
    ]
  , testGroup "extract output length"
    [ testCase "SHA-256 extract = 32 bytes" $ do
        let prk = unwrap $ hkdfExtract SHA256 "secret" "salt"
        secureBytesLength prk @?= digestSize SHA256
    , testCase "SHA-512 extract = 64 bytes" $ do
        let prk = unwrap $ hkdfExtract SHA512 "secret" "salt"
        secureBytesLength prk @?= digestSize SHA512
    , testCase "SHA-1 extract = 20 bytes" $ do
        let prk = unwrap $ hkdfExtract SHA1 "secret" "salt"
        secureBytesLength prk @?= digestSize SHA1
    ]
  , testGroup "output length"
    [ testCase "hkdf returns requested length" $ do
        let okm = unwrap $ hkdf SHA256 "secret" "salt" "info" 64
        secureBytesLength okm @?= 64
    , testCase "hkdfExpand returns requested length" $ do
        let prk = unwrap $ hkdfExtract SHA256 "secret" "salt"
            okm = unwrap $ hkdfExpand SHA256 (secureBytesToByteString prk) "info" 100
        secureBytesLength okm @?= 100
    ]
  , testGroup "SHA-512"
    [ testCase "SHA-512 full round-trip" $ do
        let ikm = "input keying material"
            salt = "salt value"
            info = "context info"
            okm = unwrap $ hkdf SHA512 ikm salt info 64
        secureBytesLength okm @?= 64
    , testCase "SHA-512 extract then expand matches full" $ do
        let ikm = "input keying material"
            salt = "salt value"
            info = "context info"
        let prk = unwrap $ hkdfExtract SHA512 ikm salt
            okm1 = unwrap $ hkdfExpand SHA512 (secureBytesToByteString prk) info 64
            okm2 = unwrap $ hkdf SHA512 ikm salt info 64
        secureBytesToByteString okm1 @?= secureBytesToByteString okm2
    ]
  , testGroup "error cases"
    [ testCase "expand rejects too-long output" $ do
        -- max output for SHA-256 is 255 * 32 = 8160
        let prk = unwrap $ hkdfExtract SHA256 "secret" "salt"
            result = hkdfExpand SHA256 (secureBytesToByteString prk) "info" 8161
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject output > 255*hashLen"
    ]
  ]
