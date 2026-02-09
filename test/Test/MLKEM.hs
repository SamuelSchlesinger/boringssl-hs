{-# LANGUAGE OverloadedStrings #-}
module Test.MLKEM (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.MLKEM

tests :: TestTree
tests = testGroup "MLKEM"
  [ testGroup "ML-KEM-768"
    [ testCase "keygen produces correct sizes" $ do
        (pub, _priv) <- generateKeyPair MLKEM768
        BS.length pub @?= publicKeyBytes MLKEM768

    , testCase "encap/decap round-trip" $ do
        (_pub, priv) <- generateKeyPair MLKEM768
        (ct, ssEncap) <- encapsulate priv
        BS.length ct @?= ciphertextBytes MLKEM768
        BS.length ssEncap @?= 32
        Right ssDecap <- decapsulate priv ct
        ssDecap @?= ssEncap

    , testCase "decap with wrong length ciphertext" $ do
        (_pub, priv) <- generateKeyPair MLKEM768
        result <- decapsulate priv "short"
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "decapsulate should reject wrong-length ciphertext"

    , testCase "different keypairs produce different shared secrets" $ do
        (_pub1, priv1) <- generateKeyPair MLKEM768
        (_pub2, priv2) <- generateKeyPair MLKEM768
        (ct1, ss1) <- encapsulate priv1
        (ct2, ss2) <- encapsulate priv2
        -- Different keys should produce different ciphertexts/secrets
        -- (with overwhelming probability)
        assertBool "different keypairs should differ" (ss1 /= ss2 || ct1 /= ct2)
    ]
  , testGroup "ML-KEM-768 encapsulatePublic"
    [ testCase "encapsulatePublic round-trip" $ do
        (pub, priv) <- generateKeyPair MLKEM768
        Right (ct, ssEncap) <- encapsulatePublic MLKEM768 pub
        Right ssDecap <- decapsulate priv ct
        ssDecap @?= ssEncap
    , testCase "encapsulatePublic rejects wrong-length key" $ do
        result <- encapsulatePublic MLKEM768 "short"
        case result of
          Left _ -> return ()
          Right _ -> assertFailure "should reject wrong-length public key"
    ]
  , testGroup "ML-KEM-1024"
    [ testCase "keygen produces correct sizes" $ do
        (pub, _priv) <- generateKeyPair MLKEM1024
        BS.length pub @?= publicKeyBytes MLKEM1024

    , testCase "encap/decap round-trip" $ do
        (_pub, priv) <- generateKeyPair MLKEM1024
        (ct, ssEncap) <- encapsulate priv
        BS.length ct @?= ciphertextBytes MLKEM1024
        BS.length ssEncap @?= 32
        Right ssDecap <- decapsulate priv ct
        ssDecap @?= ssEncap

    , testCase "decap with wrong length ciphertext" $ do
        (_pub, priv) <- generateKeyPair MLKEM1024
        result <- decapsulate priv "short"
        case result of
          Left _  -> return ()
          Right _ -> assertFailure "decapsulate should reject wrong-length ciphertext"

    , testCase "encapsulatePublic round-trip" $ do
        (pub, priv) <- generateKeyPair MLKEM1024
        Right (ct, ssEncap) <- encapsulatePublic MLKEM1024 pub
        Right ssDecap <- decapsulate priv ct
        ssDecap @?= ssEncap
    ]
  , testGroup "Constants"
    [ testCase "ML-KEM-768 public key bytes" $
        publicKeyBytes MLKEM768 @?= 1184
    , testCase "ML-KEM-768 ciphertext bytes" $
        ciphertextBytes MLKEM768 @?= 1088
    , testCase "ML-KEM-1024 public key bytes" $
        publicKeyBytes MLKEM1024 @?= 1568
    , testCase "ML-KEM-1024 ciphertext bytes" $
        ciphertextBytes MLKEM1024 @?= 1568
    ]
  ]
