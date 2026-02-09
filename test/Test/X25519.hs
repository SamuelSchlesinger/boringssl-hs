{-# LANGUAGE OverloadedStrings #-}
module Test.X25519 (tests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.X25519

hex :: ByteString -> ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

tests :: TestTree
tests = testGroup "X25519"
  [ testCase "shared secret symmetry" $ do
      -- Both parties should derive the same shared secret
      (pubA, privA) <- generateKeyPair
      (pubB, privB) <- generateKeyPair
      case (computeSharedSecret privA pubB, computeSharedSecret privB pubA) of
        (Just secretAB, Just secretBA) -> secretAB @?= secretBA
        _ -> assertFailure "computeSharedSecret returned Nothing"
  , testCase "publicFromPrivate matches generated" $ do
      (pub, priv) <- generateKeyPair
      publicFromPrivate priv @?= pub
  , testCase "RFC 7748 Section 6.1 test vector" $ do
      -- Alice's private key
      let alicePriv = hex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
          alicePub  = hex "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
          bobPriv   = hex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
          bobPub    = hex "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
          expectedSecret = hex "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
      case (privateKeyFromBytes alicePriv, privateKeyFromBytes bobPriv, publicKeyFromBytes bobPub) of
        (Just alicePrivKey, Just bobPrivKey, Just bobPubKey) -> do
          publicKeyToBytes (publicFromPrivate alicePrivKey) @?= alicePub
          publicKeyToBytes (publicFromPrivate bobPrivKey) @?= bobPub
          -- Check shared secret
          case computeSharedSecret alicePrivKey bobPubKey of
            Just secret -> secret @?= expectedSecret
            Nothing -> assertFailure "computeSharedSecret returned Nothing"
        _ -> assertFailure "key deserialization failed"
  , testGroup "Smart constructors"
    [ testCase "publicKeyFromBytes accepts 32 bytes" $ do
        let bs = BS.replicate 32 0x42
        case publicKeyFromBytes bs of
          Just _  -> return ()
          Nothing -> assertFailure "publicKeyFromBytes rejected valid 32-byte input"
    , testCase "publicKeyFromBytes rejects wrong lengths" $ do
        assertBool "should reject 0 bytes" (publicKeyFromBytes BS.empty == Nothing)
        assertBool "should reject 31 bytes" (publicKeyFromBytes (BS.replicate 31 0x00) == Nothing)
        assertBool "should reject 33 bytes" (publicKeyFromBytes (BS.replicate 33 0x00) == Nothing)
    , testCase "privateKeyFromBytes accepts 32 bytes" $ do
        let bs = BS.replicate 32 0x42
        case privateKeyFromBytes bs of
          Just _  -> return ()
          Nothing -> assertFailure "privateKeyFromBytes rejected valid 32-byte input"
    , testCase "privateKeyFromBytes rejects wrong lengths" $ do
        assertBool "should reject 0 bytes" (privateKeyFromBytes BS.empty == Nothing)
        assertBool "should reject 31 bytes" (privateKeyFromBytes (BS.replicate 31 0x00) == Nothing)
        assertBool "should reject 33 bytes" (privateKeyFromBytes (BS.replicate 33 0x00) == Nothing)
    , testCase "publicKeyToBytes round-trip" $ do
        (pub, _) <- generateKeyPair
        case publicKeyFromBytes (publicKeyToBytes pub) of
          Just pub' -> pub' @?= pub
          Nothing   -> assertFailure "publicKeyFromBytes rejected publicKeyToBytes output"
    , testCase "privateKeyToBytes round-trip" $ do
        (_, priv) <- generateKeyPair
        case privateKeyFromBytes (privateKeyToBytes priv) of
          Just priv' -> priv' @?= priv
          Nothing    -> assertFailure "privateKeyFromBytes rejected privateKeyToBytes output"
    ]
  ]
