{-# LANGUAGE OverloadedStrings #-}
module Test.SLHDSA (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Either (isLeft)
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.SecureBytes
import Crypto.BoringSSL.SLHDSA

tests :: TestTree
tests = testGroup "SLHDSA"
  [ variantTests SHA2_128S
  , testGroup "SHAKE_256F"
    [ testCase "sign/verify round-trip" $ do
        (pub, priv) <- generateKeyPair SHAKE_256F
        let msg = BS8.pack "SHAKE-256F test"
            ctx = BS.empty
        result <- sign SHAKE_256F priv msg ctx
        case result of
          Left err -> assertFailure ("sign returned Left: " ++ show err)
          Right sig -> do
            BS.length sig @?= signatureBytes SHAKE_256F
            verify pub msg sig ctx @?= True
    ]
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
      BS.length (publicKeyToBytes pub) @?= publicKeyBytes variant
      secureBytesLength priv @?= privateKeyBytes variant

  , testCase "sign/verify round-trip" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "Hello, post-quantum world!"
          ctx = BS.empty
      result <- sign variant priv msg ctx
      case result of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig -> do
          BS.length sig @?= signatureBytes variant
          verify pub msg sig ctx @?= True

  , testCase "sign/verify with context" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "context test message"
          ctx = BS8.pack "my-context"
      result <- sign variant priv msg ctx
      case result of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          verify pub msg sig ctx @?= True

  , testCase "verify rejects tampered signature" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "test message"
          ctx = BS.empty
      result <- sign variant priv msg ctx
      case result of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig -> do
          let tampered = BS.cons (BS.head sig + 1) (BS.tail sig)
          verify pub msg tampered ctx @?= False

  , testCase "verify rejects wrong message" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "original"
          ctx = BS.empty
      result <- sign variant priv msg ctx
      case result of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          verify pub "different" sig ctx @?= False

  , testCase "verify rejects wrong context" $ do
      (pub, priv) <- generateKeyPair variant
      let msg = BS8.pack "test"
          ctx1 = BS8.pack "context-a"
          ctx2 = BS8.pack "context-b"
      result <- sign variant priv msg ctx1
      case result of
        Left err -> assertFailure ("sign returned Left: " ++ show err)
        Right sig ->
          verify pub msg sig ctx2 @?= False

  , testCase "sign rejects wrong-length private key" $ do
      -- Create a SecureBytes of incorrect length (1 byte instead of privateKeyBytes)
      wrongKey <- createSecureBytes 1 $ \_ -> return ()
      result <- sign variant wrongKey "msg" ""
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "sign should reject wrong-length private key"

  , testCase "sign rejects overlong context" $ do
      (_pub, priv) <- generateKeyPair variant
      result <- sign variant priv "msg" (BS.replicate 256 0x61)
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "sign should reject a context longer than 255 bytes"

  , testCase "publicKeyFromBytes rejects wrong length" $
      assertBool "should reject wrong-length public key"
        (isLeft (publicKeyFromBytes variant "short"))

  , testCase "publicKeyFromBytes round-trips keygen output" $ do
      (pub, _priv) <- generateKeyPair variant
      publicKeyFromBytes variant (publicKeyToBytes pub) @?= Right pub
  ]
