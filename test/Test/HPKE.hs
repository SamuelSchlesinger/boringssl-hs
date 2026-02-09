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
  , testGroup "XWing"
    [ testCase "round-trip seal/open" $ roundTrip XWing HkdfSha256 Aes128Gcm
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
        Right key <- generateKey X25519HkdfSha256
        Right pub <- publicKeyBytes key
        assertBool "public key should not be empty" (not (BS.null pub))
    , testCase "private key round-trip" $ do
        Right key <- generateKey X25519HkdfSha256
        Right priv <- privateKeyBytes key
        Right key2 <- keyFromPrivate X25519HkdfSha256 priv
        Right pub1 <- publicKeyBytes key
        Right pub2 <- publicKeyBytes key2
        pub1 @?= pub2
    ]
  , testGroup "Auth mode"
    [ testCase "X25519 auth round-trip" $
        authRoundTrip X25519HkdfSha256 HkdfSha256 Aes128Gcm
    , testCase "P-256 auth round-trip" $
        authRoundTrip P256HkdfSha256 HkdfSha256 Aes128Gcm
    , testCase "auth wrong sender key fails" $ do
        -- Generate sender, recipient, and impersonator keys
        Right senderKey <- generateKey X25519HkdfSha256
        Right recipientKey <- generateKey X25519HkdfSha256
        Right imposterKey <- generateKey X25519HkdfSha256
        Right recipientPub <- publicKeyBytes recipientKey
        Right imposterPub <- publicKeyBytes imposterKey
        let info = "auth test"
        -- Sender authenticates with their key
        Right (enc, sCtx) <- setupAuthSender senderKey HkdfSha256 Aes128Gcm recipientPub info
        Right ct <- senderSeal sCtx "secret" "ad"
        -- Recipient tries to verify with the wrong sender public key
        Right rCtx <- setupAuthRecipient recipientKey HkdfSha256 Aes128Gcm enc info imposterPub
        result <- recipientOpen rCtx ct "ad"
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should not decrypt with wrong sender key"
    ]
  , testCase "wrong key fails open" $ do
      Right key1 <- generateKey X25519HkdfSha256
      Right key2 <- generateKey X25519HkdfSha256
      Right pub1 <- publicKeyBytes key1
      let info = "test info"
      Right (enc, sCtx) <- setupSender X25519HkdfSha256 HkdfSha256 Aes128Gcm pub1 info
      Right ct <- senderSeal sCtx "secret message" "ad"
      -- Try to open with the wrong key
      result <- do
        Right rCtx <- setupRecipient key2 HkdfSha256 Aes128Gcm enc info
        recipientOpen rCtx ct "ad"
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "should not decrypt with wrong key"
  ]

roundTrip :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
roundTrip kem kdf aead = do
  Right key <- generateKey kem
  Right pub <- publicKeyBytes key
  let info = "test info"
      plaintext = "Hello, HPKE!"
      ad = "associated data"
  Right (enc, sCtx) <- setupSender kem kdf aead pub info
  Right ct <- senderSeal sCtx plaintext ad
  Right rCtx <- setupRecipient key kdf aead enc info
  Right recovered <- recipientOpen rCtx ct ad
  recovered @?= plaintext

multiSealOpen :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
multiSealOpen kem kdf aead = do
  Right key <- generateKey kem
  Right pub <- publicKeyBytes key
  let info = "multi test"
  Right (enc, sCtx) <- setupSender kem kdf aead pub info
  Right rCtx <- setupRecipient key kdf aead enc info
  -- Seal/open multiple messages in order
  Right ct1 <- senderSeal sCtx "message 1" "ad1"
  Right ct2 <- senderSeal sCtx "message 2" "ad2"
  Right ct3 <- senderSeal sCtx "message 3" "ad3"
  Right pt1 <- recipientOpen rCtx ct1 "ad1"
  Right pt2 <- recipientOpen rCtx ct2 "ad2"
  Right pt3 <- recipientOpen rCtx ct3 "ad3"
  pt1 @?= "message 1"
  pt2 @?= "message 2"
  pt3 @?= "message 3"

exportAgreement :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
exportAgreement kem kdf aead = do
  Right key <- generateKey kem
  Right pub <- publicKeyBytes key
  let info = "export test"
      exportCtx = "my context"
      exportLen = 32
  Right (enc, sCtx) <- setupSender kem kdf aead pub info
  Right rCtx <- setupRecipient key kdf aead enc info
  Right sSecret <- senderExport sCtx exportCtx exportLen
  Right rSecret <- recipientExport rCtx exportCtx exportLen
  sSecret @?= rSecret
  assertBool "export should be 32 bytes" (BS.length sSecret == 32)

authRoundTrip :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> IO ()
authRoundTrip kem kdf aead = do
  Right senderKey <- generateKey kem
  Right recipientKey <- generateKey kem
  Right senderPub <- publicKeyBytes senderKey
  Right recipientPub <- publicKeyBytes recipientKey
  let info = "auth test"
      plaintext = "Hello, authenticated HPKE!"
      ad = "associated data"
  Right (enc, sCtx) <- setupAuthSender senderKey kdf aead recipientPub info
  Right ct <- senderSeal sCtx plaintext ad
  Right rCtx <- setupAuthRecipient recipientKey kdf aead enc info senderPub
  Right recovered <- recipientOpen rCtx ct ad
  recovered @?= plaintext
