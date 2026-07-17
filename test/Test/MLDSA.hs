{-# LANGUAGE OverloadedStrings #-}
module Test.MLDSA (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.MLDSA
import Crypto.BoringSSL.SecureBytes (createSecureBytes)

tests :: TestTree
tests = testGroup "MLDSA"
  [ variantTests MLDSA44
  , variantTests MLDSA65
  , variantTests MLDSA87
  , testGroup "privateKeyFromSeed"
    [ testCase "reconstruct key from seed and sign/verify (ML-DSA-65)" $ do
        Right gen <- generateKeyPair MLDSA65
        let seed = mldsaGenSeed gen
            pubKey = mldsaGenPublicKey gen
        case privateKeyFromSeed MLDSA65 seed of
          Left err -> assertFailure ("privateKeyFromSeed failed: " ++ show err)
          Right priv2 -> do
            let msg = BS8.pack "seed round-trip"
                ctx = BS.empty
            Right sig <- sign priv2 msg ctx
            verify pubKey msg sig ctx @?= True
    , testCase "reject wrong seed length (31 bytes)" $ do
        wrongSeed <- createSecureBytes 31 $ \_ -> return ()
        case privateKeyFromSeed MLDSA65 wrongSeed of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 31-byte seed"
    , testCase "reject wrong seed length (33 bytes)" $ do
        wrongSeed <- createSecureBytes 33 $ \_ -> return ()
        case privateKeyFromSeed MLDSA65 wrongSeed of
          Left _  -> return ()
          Right _ -> assertFailure "should reject 33-byte seed"
    ]
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
      Right gen <- generateKeyPair variant
      let pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          _priv = mldsaGenPrivateKey gen
      BS.length (publicKeyToBytes pub) @?= publicKeyBytes variant

  , testCase "sign/verify round-trip" $ do
      Right gen <- generateKeyPair variant
      let _pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "Hello, post-quantum world!"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      BS.length sig @?= signatureBytes variant
      Right pubKey <- return (publicKeyFromPrivate priv)
      verify pubKey msg sig ctx @?= True

  , testCase "sign/verify with context" $ do
      Right gen <- generateKeyPair variant
      let _pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "context test message"
          ctx = BS8.pack "my-application-context"
      Right sig <- sign priv msg ctx
      Right pubKey <- return (publicKeyFromPrivate priv)
      verify pubKey msg sig ctx @?= True

  , testCase "verify rejects invalid signature" $ do
      Right gen <- generateKeyPair variant
      let _pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "test message"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      -- Tamper with the signature
      let tampered = BS.cons (BS.head sig + 1) (BS.tail sig)
      Right pubKey <- return (publicKeyFromPrivate priv)
      verify pubKey msg tampered ctx @?= False

  , testCase "verify rejects wrong message" $ do
      Right gen <- generateKeyPair variant
      let _pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "original message"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      let wrongMsg = BS8.pack "different message"
      Right pubKey <- return (publicKeyFromPrivate priv)
      verify pubKey wrongMsg sig ctx @?= False

  , testCase "verify rejects wrong context" $ do
      Right gen <- generateKeyPair variant
      let _pub = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "test"
          ctx1 = BS8.pack "context-a"
          ctx2 = BS8.pack "context-b"
      Right sig <- sign priv msg ctx1
      Right pubKey <- return (publicKeyFromPrivate priv)
      verify pubKey msg sig ctx2 @?= False

  , testCase "different keys produce different signatures" $ do
      Right gen <- generateKeyPair variant
      let _pub1 = mldsaGenPublicKey gen
          _seed1 = mldsaGenSeed gen
          priv1 = mldsaGenPrivateKey gen
      Right gen <- generateKeyPair variant
      let _pub2 = mldsaGenPublicKey gen
          _seed2 = mldsaGenSeed gen
          priv2 = mldsaGenPrivateKey gen
      let msg = BS8.pack "shared message"
          ctx = BS.empty
      Right sig1 <- sign priv1 msg ctx
      Right sig2 <- sign priv2 msg ctx
      assertBool "different keys should produce different sigs" (sig1 /= sig2)

  , testCase "publicKeyFromBytes round-trip" $ do
      Right gen <- generateKeyPair variant
      let pubEncoded = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "round-trip test"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      case publicKeyFromBytes variant (publicKeyToBytes pubEncoded) of
        Left _ -> assertFailure "publicKeyFromBytes returned Left"
        Right pubKey ->
          verify pubKey msg sig ctx @?= True

  , testCase "publicKeyFromBytes rejects wrong length" $ do
      let result = publicKeyFromBytes variant "too short"
      case result of
        Left _ -> return ()
        Right _ -> assertFailure "publicKeyFromBytes should reject wrong length"

  , testCase "publicKeyFromPrivate matches publicKeyFromBytes" $ do
      Right gen <- generateKeyPair variant
      let pubEncoded = mldsaGenPublicKey gen
          _seed = mldsaGenSeed gen
          priv = mldsaGenPrivateKey gen
      let msg = BS8.pack "cross-verify test"
          ctx = BS.empty
      Right sig <- sign priv msg ctx
      Right pubFromPriv <- return (publicKeyFromPrivate priv)
      case publicKeyFromBytes variant (publicKeyToBytes pubEncoded) of
        Left _ -> assertFailure "publicKeyFromBytes returned Left"
        Right pubFromBytes -> do
          verify pubFromPriv msg sig ctx @?= True
          verify pubFromBytes msg sig ctx @?= True
  ]
