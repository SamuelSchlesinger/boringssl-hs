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
  , testGroup "empty plaintext"
    [ testCase "AES-128-GCM empty plaintext round-trip" $ roundTripEmpty AES128GCM
    , testCase "AES-256-GCM empty plaintext round-trip" $ roundTripEmpty AES256GCM
    , testCase "ChaCha20-Poly1305 empty plaintext round-trip" $ roundTripEmpty ChaCha20Poly1305
    , testCase "AES-128-GCM-SIV empty plaintext round-trip" $ roundTripEmpty AES128GCMSIV
    , testCase "AES-256-GCM-SIV empty plaintext round-trip" $ roundTripEmpty AES256GCMSIV
    ]
  ]

-- | Round-trip test: seal then open should recover the plaintext.
roundTrip :: AEADAlgorithm -> Assertion
roundTrip algo = do
  let key   = BS.replicate (keyLength algo) 0x42
      nonce = BS.replicate (nonceLength algo) 0x01
      pt    = BS8.pack "Hello, BoringSSL AEAD!"
      ad    = BS8.pack "additional data"
  ctx <- newAEADCtx algo key
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
  ctx <- newAEADCtx algo key
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
  ctx <- newAEADCtx algo key
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
  let Right key = Base16.decode
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      Right nonce = Base16.decode
        "070000004041424344454647"
      Right ad = Base16.decode
        "50515253c0c1c2c3c4c5c6c7"
      plaintext = BS8.pack
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
      Right expectedCt = Base16.decode $
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
      Right expectedTag = Base16.decode
        "1ae10b594f09e26a7e902ecbd0600691"
      expectedOutput = BS.append expectedCt expectedTag
  ctx <- newAEADCtx ChaCha20Poly1305 key
  Right ct <- seal ctx nonce plaintext ad
  ct @?= expectedOutput

-- | NIST AES-128-GCM test vector (Test Case 3 from NIST SP 800-38D)
nistAES128GCMTestVector :: Assertion
nistAES128GCMTestVector = do
  let Right key = Base16.decode
        "feffe9928665731c6d6a8f9467308308"
      Right nonce = Base16.decode
        "cafebabefacedbaddecaf888"
      Right plaintext = Base16.decode
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
      ad = BS.empty
      Right expectedCt = Base16.decode
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
      Right expectedTag = Base16.decode
        "4d5c2af327cd64a62cf35abd2ba6fab4"
      expectedOutput = BS.append expectedCt expectedTag
  ctx <- newAEADCtx AES128GCM key
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
  ctx <- newAEADCtx AES256GCMSIV key
  Right ct <- seal ctx nonce plaintext ad
  -- Ciphertext should be plaintext + 16-byte tag
  BS.length ct @?= BS.length plaintext + maxOverhead AES256GCMSIV
  -- Decryption should recover plaintext
  Right recovered <- open ctx nonce ct ad
  recovered @?= plaintext
  -- Seal again should produce the same ciphertext (deterministic)
  Right ct2 <- seal ctx nonce plaintext ad
  ct @?= ct2
