{-# LANGUAGE OverloadedStrings #-}
module Test.X25519 (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.X25519

tests :: TestTree
tests = testGroup "X25519"
  [ testCase "shared secret symmetry" $ do
      -- Both parties should derive the same shared secret
      (pubA, privA) <- generateKeyPair
      (pubB, privB) <- generateKeyPair
      let Just secretAB = computeSharedSecret privA pubB
          Just secretBA = computeSharedSecret privB pubA
      secretAB @?= secretBA
  , testCase "publicFromPrivate matches generated" $ do
      (pub, priv) <- generateKeyPair
      publicFromPrivate priv @?= pub
  , testCase "RFC 7748 Section 6.1 test vector" $ do
      -- Alice's private key
      let Right alicePriv = Base16.decode "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
          Right alicePub  = Base16.decode "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
          Right bobPriv   = Base16.decode "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
          Right bobPub    = Base16.decode "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
          Right expectedSecret = Base16.decode "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
      -- Check public key derivation
      let PublicKey derivedAlicePub = publicFromPrivate (PrivateKey alicePriv)
      derivedAlicePub @?= alicePub
      let PublicKey derivedBobPub = publicFromPrivate (PrivateKey bobPriv)
      derivedBobPub @?= bobPub
      -- Check shared secret
      let Just secret = computeSharedSecret (PrivateKey alicePriv) (PublicKey bobPub)
      secret @?= expectedSecret
  ]
