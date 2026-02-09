{-# LANGUAGE OverloadedStrings #-}
module Test.ECDH (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.ECDH

tests :: TestTree
tests = testGroup "ECDH"
  [ testCase "P-256 key agreement symmetry" $ do
      Right kpA <- generateECKeyPair P256
      Right kpB <- generateECKeyPair P256
      Right pubA <- ecPublicKeyOfPair kpA
      Right pubB <- ecPublicKeyOfPair kpB
      Right secretAB <- ecdhComputeSecret kpA pubB 32
      Right secretBA <- ecdhComputeSecret kpB pubA 32
      secretAB @?= secretBA
  , testCase "P-384 key agreement symmetry" $ do
      Right kpA <- generateECKeyPair P384
      Right kpB <- generateECKeyPair P384
      Right pubA <- ecPublicKeyOfPair kpA
      Right pubB <- ecPublicKeyOfPair kpB
      Right secretAB <- ecdhComputeSecret kpA pubB 48
      Right secretBA <- ecdhComputeSecret kpB pubA 48
      secretAB @?= secretBA
  , testCase "P-521 key agreement symmetry" $ do
      Right kpA <- generateECKeyPair P521
      Right kpB <- generateECKeyPair P521
      Right pubA <- ecPublicKeyOfPair kpA
      Right pubB <- ecPublicKeyOfPair kpB
      Right secretAB <- ecdhComputeSecret kpA pubB 64
      Right secretBA <- ecdhComputeSecret kpB pubA 64
      secretAB @?= secretBA
  , testCase "P-256 key serialization round-trip" $ do
      Right kpA <- generateECKeyPair P256
      Right kpB <- generateECKeyPair P256
      -- Serialize and deserialize public keys
      Right pubBytesA <- ecPublicKeyBytes kpA
      Right pubBytesB <- ecPublicKeyBytes kpB
      Right pubA <- ecPublicKeyFromBytes P256 pubBytesA
      Right pubB <- ecPublicKeyFromBytes P256 pubBytesB
      -- Shared secret should still agree
      Right secretAB <- ecdhComputeSecret kpA pubB 32
      Right secretBA <- ecdhComputeSecret kpB pubA 32
      secretAB @?= secretBA
  , testCase "P-256 private key serialization round-trip" $ do
      Right kpA <- generateECKeyPair P256
      Right kpB <- generateECKeyPair P256
      Right privBytesA <- ecPrivateKeyBytes kpA
      Right pubB <- ecPublicKeyOfPair kpB
      -- Reconstruct key pair from private bytes
      Right kpA2 <- ecKeyPairFromPrivateBytes P256 privBytesA
      Right secret1 <- ecdhComputeSecret kpA pubB 32
      Right secret2 <- ecdhComputeSecret kpA2 pubB 32
      secret1 @?= secret2
  , testGroup "Safety"
    [ testCase "rejects invalid output length 16" $ do
        Right kpA <- generateECKeyPair P256
        Right kpB <- generateECKeyPair P256
        Right pubB <- ecPublicKeyOfPair kpB
        result <- ecdhComputeSecret kpA pubB 16
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject output length 16"
    , testCase "rejects invalid output length 0" $ do
        Right kpA <- generateECKeyPair P256
        Right kpB <- generateECKeyPair P256
        Right pubB <- ecPublicKeyOfPair kpB
        result <- ecdhComputeSecret kpA pubB 0
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "should reject output length 0"
    ]
  , testGroup "output length"
    [ testCase "P-256 secret is 32 bytes" $ do
        Right kpA <- generateECKeyPair P256
        Right kpB <- generateECKeyPair P256
        Right pubB <- ecPublicKeyOfPair kpB
        Right secret <- ecdhComputeSecret kpA pubB 32
        BS.length secret @?= 32
    , testCase "P-384 secret is 48 bytes" $ do
        Right kpA <- generateECKeyPair P384
        Right kpB <- generateECKeyPair P384
        Right pubB <- ecPublicKeyOfPair kpB
        Right secret <- ecdhComputeSecret kpA pubB 48
        BS.length secret @?= 48
    , testCase "P-521 secret is 64 bytes" $ do
        Right kpA <- generateECKeyPair P521
        Right kpB <- generateECKeyPair P521
        Right pubB <- ecPublicKeyOfPair kpB
        Right secret <- ecdhComputeSecret kpA pubB 64
        BS.length secret @?= 64
    ]
  , testGroup "raw ECDH"
    [ testCase "P-256 raw symmetry" $ do
        Right kpA <- generateECKeyPair P256
        Right kpB <- generateECKeyPair P256
        Right pubA <- ecPublicKeyOfPair kpA
        Right pubB <- ecPublicKeyOfPair kpB
        Right rawAB <- ecdhComputeRawSecret kpA pubB
        Right rawBA <- ecdhComputeRawSecret kpB pubA
        rawAB @?= rawBA
    , testCase "P-384 raw symmetry" $ do
        Right kpA <- generateECKeyPair P384
        Right kpB <- generateECKeyPair P384
        Right pubA <- ecPublicKeyOfPair kpA
        Right pubB <- ecPublicKeyOfPair kpB
        Right rawAB <- ecdhComputeRawSecret kpA pubB
        Right rawBA <- ecdhComputeRawSecret kpB pubA
        rawAB @?= rawBA
    , testCase "P-256 raw output is 32 bytes" $ do
        Right kpA <- generateECKeyPair P256
        Right kpB <- generateECKeyPair P256
        Right pubB <- ecPublicKeyOfPair kpB
        Right raw <- ecdhComputeRawSecret kpA pubB
        BS.length raw @?= 32
    , testCase "P-384 raw output is 48 bytes" $ do
        Right kpA <- generateECKeyPair P384
        Right kpB <- generateECKeyPair P384
        Right pubB <- ecPublicKeyOfPair kpB
        Right raw <- ecdhComputeRawSecret kpA pubB
        BS.length raw @?= 48
    , testCase "P-521 raw output is 66 bytes" $ do
        Right kpA <- generateECKeyPair P521
        Right kpB <- generateECKeyPair P521
        Right pubB <- ecPublicKeyOfPair kpB
        Right raw <- ecdhComputeRawSecret kpA pubB
        BS.length raw @?= 66
    ]
  , testCase "different key pairs produce different secrets" $ do
      Right kpA <- generateECKeyPair P256
      Right kpB <- generateECKeyPair P256
      Right kpC <- generateECKeyPair P256
      Right pubB <- ecPublicKeyOfPair kpB
      Right pubC <- ecPublicKeyOfPair kpC
      Right secretAB <- ecdhComputeSecret kpA pubB 32
      Right secretAC <- ecdhComputeSecret kpA pubC 32
      assertBool "different peers should give different secrets" (secretAB /= secretAC)
  ]
