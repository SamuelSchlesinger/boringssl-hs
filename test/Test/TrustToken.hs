{-# LANGUAGE OverloadedStrings #-}
module Test.TrustToken (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Random (randomBytes)
import Crypto.BoringSSL.TrustToken

tests :: TestTree
tests = testGroup "TrustToken"
  [ testCase "ExperimentV2VOPRF full round-trip" $ fullRoundTrip ExperimentV2VOPRF
  , testCase "ExperimentV2PMB full round-trip" $ fullRoundTrip ExperimentV2PMB
  , testCase "PstV1VOPRF full round-trip" $ fullRoundTrip PstV1VOPRF
  , testCase "PstV1PMB full round-trip" $ fullRoundTrip PstV1PMB
  , testCase "batch issuance" $ batchIssuance ExperimentV2VOPRF
  ]

fullRoundTrip :: TrustTokenMethod -> IO ()
fullRoundTrip method = do
  -- Generate keys
  (privKey, pubKey) <- generateKey method 1

  -- Set up client
  client <- newClient method 10
  _ <- clientAddKey client pubKey

  -- Set up issuer
  issuer <- newIssuer method 10
  issuerAddKey issuer privKey
  metadataKey <- randomBytes 32
  issuerSetMetadataKey issuer metadataKey

  -- Client begins issuance
  request <- beginIssuance client 1

  -- Issuer issues tokens (public_metadata = key ID = 1)
  Just (response, _tokensIssued) <- issue issuer request 1 0 1

  -- Client finishes issuance
  Just (tokens, _keyIdx) <- finishIssuance client response
  assertBool "should get at least one token" (not (null tokens))

  let token = head tokens

  -- Client begins redemption
  redemptionReq <- beginRedemption client token "client data"

  -- Issuer redeems
  Just (_pubMeta, _privMeta, _tokenData, clientData) <- redeem issuer redemptionReq
  clientData @?= "client data"

batchIssuance :: TrustTokenMethod -> IO ()
batchIssuance method = do
  (privKey, pubKey) <- generateKey method 1

  client <- newClient method 10
  _ <- clientAddKey client pubKey

  issuer <- newIssuer method 10
  issuerAddKey issuer privKey
  metadataKey <- randomBytes 32
  issuerSetMetadataKey issuer metadataKey

  -- Request 5 tokens
  request <- beginIssuance client 5

  Just (response, tokensIssued) <- issue issuer request 1 0 5
  assertBool "should issue multiple tokens" (tokensIssued > 0)

  Just (tokens, _keyIdx) <- finishIssuance client response
  assertBool "should get multiple tokens" (length tokens > 0)
