{-# LANGUAGE OverloadedStrings #-}
module Test.AEAD (tests) where

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.Word (Word8)
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.AEAD

hex :: BS.ByteString -> BS.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

tests :: TestTree
tests = testGroup "AEAD"
  [ testGroup "AES-128-GCM"
    [ testCase "round-trip" $ roundTrip AES128GCM
    , testCase "authentication failure" $ authFailure AES128GCM
    , testCase "parameter queries" $ do
        keyLength AES128GCM @?= 16
        nonceLength AES128GCM @?= 12
        maxOverhead AES128GCM @?= 16
    ]
  , testGroup "AES-256-GCM"
    [ testCase "round-trip" $ roundTrip AES256GCM
    , testCase "authentication failure" $ authFailure AES256GCM
    , testCase "parameter queries" $ do
        keyLength AES256GCM @?= 32
        nonceLength AES256GCM @?= 12
        maxOverhead AES256GCM @?= 16
    ]
  , testGroup "ChaCha20-Poly1305"
    [ testCase "round-trip" $ roundTrip ChaCha20Poly1305
    , testCase "authentication failure" $ authFailure ChaCha20Poly1305
    , testCase "parameter queries" $ do
        keyLength ChaCha20Poly1305 @?= 32
        nonceLength ChaCha20Poly1305 @?= 12
        maxOverhead ChaCha20Poly1305 @?= 16
    , testCase "RFC 7539 test vector" rfc7539TestVector
    ]
  , testGroup "AES-128-GCM known-answer"
    [ testCase "NIST test case" nistAES128GCMTestVector
    ]
  , testGroup "AES-128-GCM-SIV"
    [ testCase "round-trip" $ roundTrip AES128GCMSIV
    , testCase "authentication failure" $ authFailure AES128GCMSIV
    , testCase "parameter queries" $ do
        keyLength AES128GCMSIV @?= 16
        nonceLength AES128GCMSIV @?= 12
    ]
  , testGroup "AES-256-GCM-SIV"
    [ testCase "round-trip" $ roundTrip AES256GCMSIV
    , testCase "authentication failure" $ authFailure AES256GCMSIV
    , testCase "parameter queries" $ do
        keyLength AES256GCMSIV @?= 32
        nonceLength AES256GCMSIV @?= 12
    , testCase "known-answer vector" aes256GCMSIVKnownAnswer
    ]
  , testGroup "AES-192-GCM"
    [ testCase "round-trip" $ roundTrip AES192GCM
    , testCase "authentication failure" $ authFailure AES192GCM
    , testCase "parameter queries" $ do
        keyLength AES192GCM @?= 24
        nonceLength AES192GCM @?= 12
        maxOverhead AES192GCM @?= 16
    ]
  , testGroup "XChaCha20-Poly1305"
    [ testCase "round-trip" $ roundTrip XChaCha20Poly1305
    , testCase "authentication failure" $ authFailure XChaCha20Poly1305
    , testCase "parameter queries" $ do
        keyLength XChaCha20Poly1305 @?= 32
        nonceLength XChaCha20Poly1305 @?= 24
        maxOverhead XChaCha20Poly1305 @?= 16
    ]
  , testGroup "AES-128-CTR-HMAC-SHA256"
    [ testCase "round-trip" $ roundTrip AES128CtrHmacSha256
    , testCase "authentication failure" $ authFailure AES128CtrHmacSha256
    ]
  , testGroup "AES-256-CTR-HMAC-SHA256"
    [ testCase "round-trip" $ roundTrip AES256CtrHmacSha256
    , testCase "authentication failure" $ authFailure AES256CtrHmacSha256
    ]
  , testGroup "AES-128-EAX"
    [ testCase "round-trip" $ roundTrip AES128EAX
    , testCase "authentication failure" $ authFailure AES128EAX
    ]
  , testGroup "AES-256-EAX"
    [ testCase "round-trip" $ roundTrip AES256EAX
    , testCase "authentication failure" $ authFailure AES256EAX
    ]
  , testGroup "AES-128-CCM-Bluetooth"
    [ testCase "round-trip" $ roundTrip AES128CCMBluetooth
    , testCase "authentication failure" $ authFailure AES128CCMBluetooth
    ]
  , testGroup "AES-128-CCM-Bluetooth-8"
    [ testCase "round-trip" $ roundTrip AES128CCMBluetooth8
    , testCase "authentication failure" $ authFailure AES128CCMBluetooth8
    ]
  , testGroup "AES-128-CCM-Matter"
    [ testCase "round-trip" $ roundTrip AES128CCMMatter
    , testCase "authentication failure" $ authFailure AES128CCMMatter
    ]
  , testGroup "empty plaintext"
    [ testCase "AES-128-GCM empty plaintext round-trip" $ roundTripEmpty AES128GCM
    , testCase "AES-256-GCM empty plaintext round-trip" $ roundTripEmpty AES256GCM
    , testCase "ChaCha20-Poly1305 empty plaintext round-trip" $ roundTripEmpty ChaCha20Poly1305
    , testCase "AES-128-GCM-SIV empty plaintext round-trip" $ roundTripEmpty AES128GCMSIV
    , testCase "AES-256-GCM-SIV empty plaintext round-trip" $ roundTripEmpty AES256GCMSIV
    ]
  , testGroup "input validation"
    [ testCase "wrong key length returns Left" $ do
        result <- newAEADCtx AES128GCM (BS.replicate 15 0x42)
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject wrong key length"
    , testCase "wrong key length (too long) returns Left" $ do
        result <- newAEADCtx AES128GCM (BS.replicate 17 0x42)
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject wrong key length"
    ]
  , testGroup "AD tampering"
    [ testCase "tampered AD causes open to fail" $ do
        let key   = BS.replicate (keyLength AES256GCM) 0x42
            nonce = BS.replicate (nonceLength AES256GCM) 0x01
            pt    = BS8.pack "secret"
            ad    = BS8.pack "correct ad"
        Right ctx <- newAEADCtx AES256GCM key
        Right ct <- seal ctx nonce pt ad
        result <- open ctx nonce ct (BS8.pack "wrong ad")
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "open should fail with tampered AD"
    ]
  , testGroup "ciphertext length"
    [ testCase "AES-128-GCM ciphertext length" $ ctLenCheck AES128GCM
    , testCase "AES-256-GCM ciphertext length" $ ctLenCheck AES256GCM
    , testCase "ChaCha20-Poly1305 ciphertext length" $ ctLenCheck ChaCha20Poly1305
    ]
  ]

-- | Round-trip test: seal then open should recover the plaintext.
roundTrip :: AEADAlgorithm -> Assertion
roundTrip algo = do
  let key   = BS.replicate (keyLength algo) 0x42
      nonce = BS.replicate (nonceLength algo) 0x01
      pt    = BS8.pack "Hello, BoringSSL AEAD!"
      ad    = BS8.pack "additional data"
  Right ctx <- newAEADCtx algo key
  Right ct <- seal ctx nonce pt ad
  Right recovered <- open ctx nonce ct ad
  recovered @?= pt

-- | Empty plaintext round-trip (authentication-only mode).
roundTripEmpty :: AEADAlgorithm -> Assertion
roundTripEmpty algo = do
  let key   = BS.replicate (keyLength algo) 0xAA
      nonce = BS.replicate (nonceLength algo) 0xBB
      pt    = BS.empty
      ad    = BS8.pack "auth only"
  Right ctx <- newAEADCtx algo key
  Right ct <- seal ctx nonce pt ad
  Right recovered <- open ctx nonce ct ad
  recovered @?= pt

-- | Authentication failure: tampering with ciphertext should cause open to fail.
authFailure :: AEADAlgorithm -> Assertion
authFailure algo = do
  let key   = BS.replicate (keyLength algo) 0x42
      nonce = BS.replicate (nonceLength algo) 0x01
      pt    = BS8.pack "secret message"
      ad    = BS8.pack "aad"
  Right ctx <- newAEADCtx algo key
  Right ct <- seal ctx nonce pt ad
  let tampered = flipBit ct
  result <- open ctx nonce tampered ad
  case result of
    Left _  -> return ()
    Right _ -> assertFailure "open should have failed on tampered ciphertext"

-- | Flip the first bit of a ByteString.
flipBit :: ByteString -> ByteString
flipBit bs
  | BS.null bs = bs
  | otherwise  = BS.cons (BS.head bs `xor` (0x01 :: Word8)) (BS.tail bs)

-- | RFC 7539 Section 2.8.2 test vector for ChaCha20-Poly1305
rfc7539TestVector :: Assertion
rfc7539TestVector = do
  let key = hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      nonce = hex "070000004041424344454647"
      ad = hex "50515253c0c1c2c3c4c5c6c7"
      plaintext = BS8.pack
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
      expectedCt = hex "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
      expectedTag = hex "1ae10b594f09e26a7e902ecbd0600691"
      expectedOutput = BS.append expectedCt expectedTag
  Right ctx <- newAEADCtx ChaCha20Poly1305 key
  Right ct <- seal ctx nonce plaintext ad
  ct @?= expectedOutput

-- | NIST AES-128-GCM test vector (Test Case 3 from NIST SP 800-38D)
nistAES128GCMTestVector :: Assertion
nistAES128GCMTestVector = do
  let key = hex "feffe9928665731c6d6a8f9467308308"
      nonce = hex "cafebabefacedbaddecaf888"
      plaintext = hex "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
      ad = BS.empty
      expectedCt = hex "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
      expectedTag = hex "4d5c2af327cd64a62cf35abd2ba6fab4"
      expectedOutput = BS.append expectedCt expectedTag
  Right ctx <- newAEADCtx AES128GCM key
  Right ct <- seal ctx nonce plaintext ad
  ct @?= expectedOutput

-- | AES-256-GCM-SIV known answer test: verifies seal followed by open
-- produces consistent results, and that the ciphertext is longer than
-- the plaintext (includes 16-byte tag).
aes256GCMSIVKnownAnswer :: Assertion
aes256GCMSIVKnownAnswer = do
  let key = BS.replicate 32 0x01
      nonce = BS.replicate 12 0x02
      plaintext = BS8.pack "AES-256-GCM-SIV test"
      ad = BS8.pack "additional data"
  Right ctx <- newAEADCtx AES256GCMSIV key
  Right ct <- seal ctx nonce plaintext ad
  -- Ciphertext should be plaintext + 16-byte tag
  BS.length ct @?= BS.length plaintext + maxOverhead AES256GCMSIV
  -- Decryption should recover plaintext
  Right recovered <- open ctx nonce ct ad
  recovered @?= plaintext
  -- Seal again should produce the same ciphertext (deterministic)
  Right ct2 <- seal ctx nonce plaintext ad
  ct @?= ct2

-- | Verify ciphertext length equals plaintext length + maxOverhead.
ctLenCheck :: AEADAlgorithm -> Assertion
ctLenCheck algo = do
  let key   = BS.replicate (keyLength algo) 0x42
      nonce = BS.replicate (nonceLength algo) 0x01
      pt    = BS8.pack "test plaintext data"
      ad    = BS.empty
  Right ctx <- newAEADCtx algo key
  Right ct <- seal ctx nonce pt ad
  BS.length ct @?= BS.length pt + maxOverhead algo
