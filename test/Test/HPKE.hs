{-# LANGUAGE OverloadedStrings #-}
module Test.HPKE (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.HPKE

tests :: TestTree
tests = testGroup "HPKE"
  [ testGroup "X25519"
    [ testCase "round-trip seal/open" $ roundTrip X25519HkdfSha256 HkdfSha256 Aes128Gcm
    , testCase "multiple seal/open" $ multiSealOpen X25519HkdfSha256 HkdfSha256 Aes128Gcm
    , testCase "export secret agreement" $ exportAgreement X25519HkdfSha256 HkdfSha256 Aes128Gcm
    ]
  , testGroup "P-256"
    [ testCase "round-trip seal/open" $ roundTrip P256HkdfSha256 HkdfSha256 Aes128Gcm
    , testCase "multiple seal/open" $ multiSealOpen P256HkdfSha256 HkdfSha256 Aes128Gcm
    ]
  , testGroup "MLKEM768"
    [ testCase "round-trip seal/open" $ roundTrip MLKEM768 HkdfSha256 Aes128Gcm
    ]
  , testGroup "MLKEM1024"
    [ testCase "round-trip seal/open" $ roundTrip MLKEM1024 HkdfSha256 Aes128Gcm
    ]
  , testGroup "AEAD variants"
    [ testCase "AES-256-GCM" $ roundTrip X25519HkdfSha256 HkdfSha256 Aes256Gcm
    , testCase "ChaCha20-Poly1305" $ roundTrip X25519HkdfSha256 HkdfSha256 ChaChaPoly
    ]
  , testGroup "Key serialization"
    [ testCase "public key round-trip" $ do
        key <- generateKey X25519HkdfSha256
        pub <- publicKeyBytes key
        assertBool "public key should not be empty" (not (BS.null pub))
    , testCase "private key round-trip" $ do
        key <- generateKey X25519HkdfSha256
        priv <- privateKeyBytes key
        key2 <- keyFromPrivate X25519HkdfSha256 priv
        pub1 <- publicKeyBytes key
        pub2 <- publicKeyBytes key2
        pub1 @?= pub2
    ]
  , testCase "wrong key fails open" $ do
      key1 <- generateKey X25519HkdfSha256
      key2 <- generateKey X25519HkdfSha256
      pub1 <- publicKeyBytes key1
      let info = "test info"
      (enc, sCtx) <- setupSender X25519HkdfSha256 HkdfSha256 Aes128Gcm pub1 info
      ct <- senderSeal sCtx "secret message" "ad"
      -- Try to open with the wrong key
      result <- do
        rCtx <- setupRecipient key2 HkdfSha256 Aes128Gcm enc info
        recipientOpen rCtx ct "ad"
      case result of
        Nothing -> return ()
        Just _  -> assertFailure "should not decrypt with wrong key"
  ]

roundTrip :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
roundTrip kem kdf aead = do
  key <- generateKey kem
  pub <- publicKeyBytes key
  let info = "test info"
      plaintext = "Hello, HPKE!"
      ad = "associated data"
  (enc, sCtx) <- setupSender kem kdf aead pub info
  ct <- senderSeal sCtx plaintext ad
  rCtx <- setupRecipient key kdf aead enc info
  Just recovered <- recipientOpen rCtx ct ad
  recovered @?= plaintext

multiSealOpen :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
multiSealOpen kem kdf aead = do
  key <- generateKey kem
  pub <- publicKeyBytes key
  let info = "multi test"
  (enc, sCtx) <- setupSender kem kdf aead pub info
  rCtx <- setupRecipient key kdf aead enc info
  -- Seal/open multiple messages in order
  ct1 <- senderSeal sCtx "message 1" "ad1"
  ct2 <- senderSeal sCtx "message 2" "ad2"
  ct3 <- senderSeal sCtx "message 3" "ad3"
  Just pt1 <- recipientOpen rCtx ct1 "ad1"
  Just pt2 <- recipientOpen rCtx ct2 "ad2"
  Just pt3 <- recipientOpen rCtx ct3 "ad3"
  pt1 @?= "message 1"
  pt2 @?= "message 2"
  pt3 @?= "message 3"

exportAgreement :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
exportAgreement kem kdf aead = do
  key <- generateKey kem
  pub <- publicKeyBytes key
  let info = "export test"
      exportCtx = "my context"
      exportLen = 32
  (enc, sCtx) <- setupSender kem kdf aead pub info
  rCtx <- setupRecipient key kdf aead enc info
  sSecret <- senderExport sCtx exportCtx exportLen
  rSecret <- recipientExport rCtx exportCtx exportLen
  sSecret @?= rSecret
  assertBool "export should be 32 bytes" (BS.length sSecret == 32)
