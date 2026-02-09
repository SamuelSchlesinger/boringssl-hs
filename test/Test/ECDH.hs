{-# LANGUAGE OverloadedStrings #-}
module Test.ECDH (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.ECDH

tests :: TestTree
tests = testGroup "ECDH"
  [ testCase "P-256 key agreement symmetry" $ do
      kpA <- generateECKeyPair P256
      kpB <- generateECKeyPair P256
      pubA <- ecPublicKeyOfPair kpA
      pubB <- ecPublicKeyOfPair kpB
      Right secretAB <- ecdhComputeSecret kpA pubB 32
      Right secretBA <- ecdhComputeSecret kpB pubA 32
      secretAB @?= secretBA
  , testCase "P-384 key agreement symmetry" $ do
      kpA <- generateECKeyPair P384
      kpB <- generateECKeyPair P384
      pubA <- ecPublicKeyOfPair kpA
      pubB <- ecPublicKeyOfPair kpB
      Right secretAB <- ecdhComputeSecret kpA pubB 48
      Right secretBA <- ecdhComputeSecret kpB pubA 48
      secretAB @?= secretBA
  ]
