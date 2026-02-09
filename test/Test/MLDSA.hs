{-# LANGUAGE OverloadedStrings #-}
module Test.MLDSA (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.MLDSA

tests :: TestTree
tests = testGroup "MLDSA"
  [ variantTests MLDSA44
  , variantTests MLDSA65
  , variantTests MLDSA87
  , testGroup "Constants"
    [ testCase "ML-DSA-44 public key bytes" $
        publicKeyBytes MLDSA44 @?= 1312
    , testCase "ML-DSA-44 signature bytes" $
        signatureBytes MLDSA44 @?= 2420
    , testCase "ML-DSA-65 public key bytes" $
        publicKeyBytes MLDSA65 @?= 1952
    , testCase "ML-DSA-65 signature bytes" $
        signatureBytes MLDSA65 @?= 3309
    , testCase "ML-DSA-87 public key bytes" $
        publicKeyBytes MLDSA87 @?= 2592
    , testCase "ML-DSA-87 signature bytes" $
        signatureBytes MLDSA87 @?= 4627
    , testCase "seed bytes" $
        seedBytes @?= 32
    ]
  ]

variantTests :: MLDSAVariant -> TestTree
variantTests variant = testGroup (show variant)
  [ testCase "keygen produces correct public key size" $ do
      Right (pub, _seed, _priv) <- generateKeyPair variant
      BS.length pub @?= publicKeyBytes variant

  , testCase "sign/verify round-trip" $ do
      Right (_pub, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "Hello, post-quantum world!"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      BS.length sig @?= signatureBytes variant
      Right pubKey <- return (publicKeyFromPrivate priv)
      let valid = verify pubKey sig msg ctx
      assertBool "signature should be valid" valid

  , testCase "sign/verify with context" $ do
      Right (_pub, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "context test message"
          ctx = BS8.pack "my-application-context"
      Right sig <- sign priv msg ctx
      Right pubKey <- return (publicKeyFromPrivate priv)
      let valid = verify pubKey sig msg ctx
      assertBool "signature with context should be valid" valid

  , testCase "verify rejects invalid signature" $ do
      Right (_pub, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "test message"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      -- Tamper with the signature
      let tampered = BS.cons (BS.head sig + 1) (BS.tail sig)
      Right pubKey <- return (publicKeyFromPrivate priv)
      let valid = verify pubKey tampered msg ctx
      assertBool "tampered signature should be invalid" (not valid)

  , testCase "verify rejects wrong message" $ do
      Right (_pub, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "original message"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      let wrongMsg = BS8.pack "different message"
      Right pubKey <- return (publicKeyFromPrivate priv)
      let valid = verify pubKey sig wrongMsg ctx
      assertBool "wrong message should fail" (not valid)

  , testCase "verify rejects wrong context" $ do
      Right (_pub, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "test"
          ctx1 = BS8.pack "context-a"
          ctx2 = BS8.pack "context-b"
      Right sig <- sign priv msg ctx1
      Right pubKey <- return (publicKeyFromPrivate priv)
      let valid = verify pubKey sig msg ctx2
      assertBool "wrong context should fail" (not valid)

  , testCase "different keys produce different signatures" $ do
      Right (_pub1, _seed1, priv1) <- generateKeyPair variant
      Right (_pub2, _seed2, priv2) <- generateKeyPair variant
      let msg = BS8.pack "shared message"
          ctx = BS.empty
      Right sig1 <- sign priv1 msg ctx
      Right sig2 <- sign priv2 msg ctx
      assertBool "different keys should produce different sigs" (sig1 /= sig2)

  , testCase "publicKeyFromBytes round-trip" $ do
      Right (pubEncoded, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "round-trip test"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      case publicKeyFromBytes variant pubEncoded of
        Left _ -> assertFailure "publicKeyFromBytes returned Left"
        Right pubKey -> do
          let valid = verify pubKey sig msg ctx
          assertBool "verify with parsed public key should succeed" valid

  , testCase "publicKeyFromBytes rejects wrong length" $ do
      let result = publicKeyFromBytes variant "too short"
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "publicKeyFromBytes should reject wrong length"

  , testCase "publicKeyFromPrivate matches publicKeyFromBytes" $ do
      Right (pubEncoded, _seed, priv) <- generateKeyPair variant
      let msg = BS8.pack "cross-verify test"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      Right pubFromPriv <- return (publicKeyFromPrivate priv)
      case publicKeyFromBytes variant pubEncoded of
        Left _ -> assertFailure "publicKeyFromBytes returned Left"
        Right pubFromBytes -> do
          let valid1 = verify pubFromPriv sig msg ctx
          let valid2 = verify pubFromBytes sig msg ctx
          assertBool "verify via publicKeyFromPrivate" valid1
          assertBool "verify via publicKeyFromBytes" valid2
  ]
