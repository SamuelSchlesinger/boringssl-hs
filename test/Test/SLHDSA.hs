{-# LANGUAGE OverloadedStrings #-}
module Test.SLHDSA (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.SLHDSA

tests :: TestTree
tests = testGroup "SLHDSA"
  [ variantTests SHA2_128S
  -- SHAKE_256F signing is extremely slow (~seconds), so we only test SHA2_128S
  -- in CI. Uncomment for thorough local testing:
  -- , variantTests SHAKE_256F
  , testGroup "Constants"
    [ testCase "SHA2-128S public key bytes" $
        publicKeyBytes SHA2_128S @?= 32
    , testCase "SHA2-128S private key bytes" $
        privateKeyBytes SHA2_128S @?= 64
    , testCase "SHA2-128S signature bytes" $
        signatureBytes SHA2_128S @?= 7856
    , testCase "SHAKE-256F public key bytes" $
        publicKeyBytes SHAKE_256F @?= 64
    , testCase "SHAKE-256F private key bytes" $
        privateKeyBytes SHAKE_256F @?= 128
    , testCase "SHAKE-256F signature bytes" $
        signatureBytes SHAKE_256F @?= 49856
    ]
  ]

variantTests :: SLHDSAVariant -> TestTree
variantTests variant = testGroup (show variant)
  [ testCase "keygen produces correct sizes" $ do
      (pub, priv) <- generateKeyPair variant
      BS.length pub @?= publicKeyBytes variant
      BS.length priv @?= privateKeyBytes variant

  , testCase "sign/verify round-trip" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "Hello, post-quantum world!"
          ctx = BS.empty
      case sign variant priv msg ctx of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig -> do
          BS.length sig @?= signatureBytes variant
          assertBool "signature should be valid" (verify variant pub sig msg ctx)

  , testCase "sign/verify with context" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "context test message"
          ctx = BS8.pack "my-context"
      case sign variant priv msg ctx of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          assertBool "signature with context should be valid"
            (verify variant pub sig msg ctx)

  , testCase "verify rejects tampered signature" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "test message"
          ctx = BS.empty
      case sign variant priv msg ctx of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig -> do
          let tampered = BS.cons (BS.head sig + 1) (BS.tail sig)
          assertBool "tampered signature should be invalid"
            (not (verify variant pub tampered msg ctx))

  , testCase "verify rejects wrong message" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "original"
          ctx = BS.empty
      case sign variant priv msg ctx of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          assertBool "wrong message should fail"
            (not (verify variant pub sig "different" ctx))

  , testCase "verify rejects wrong context" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "test"
          ctx1 = BS8.pack "context-a"
          ctx2 = BS8.pack "context-b"
      case sign variant priv msg ctx1 of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          assertBool "wrong context should fail"
            (not (verify variant pub sig msg ctx2))

  , testCase "sign rejects wrong-length private key" $ do
      let result = sign variant "too short" "msg" ""
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "sign should reject wrong-length private key"

  , testCase "verify rejects wrong-length public key" $ do
      assertBool "wrong-length public key should fail"
        (not (verify variant "short" "sig" "msg" ""))
  ]
