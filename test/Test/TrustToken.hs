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
  Right (privKey, pubKey) <- generateKey method 1

  -- Set up client
  Right client <- newClient method 10
  _ <- clientAddKey client pubKey

  -- Set up issuer
  Right issuer <- newIssuer method 10
  Right () <- issuerAddKey issuer privKey
  metadataKey <- randomBytes 32
  Right () <- issuerSetMetadataKey issuer metadataKey

  -- Client begins issuance
  Right request <- beginIssuance client 1

  -- Issuer issues tokens (public_metadata = key ID = 1)
  Right (response, _tokensIssued) <- issue issuer request 1 0 1

  -- Client finishes issuance
  Right (tokens, _keyIdx) <- finishIssuance client response
  token <- case tokens of
    []    -> assertFailure "should get at least one token"
    t : _ -> pure t

  -- Client begins redemption
  Right redemptionReq <- beginRedemption client token "client data"

  -- Issuer redeems
  Right (_pubMeta, _privMeta, _tokenData, clientData) <- redeem issuer redemptionReq
  clientData @?= "client data"

batchIssuance :: TrustTokenMethod -> IO ()
batchIssuance method = do
  Right (privKey, pubKey) <- generateKey method 1

  Right client <- newClient method 10
  _ <- clientAddKey client pubKey

  Right issuer <- newIssuer method 10
  Right () <- issuerAddKey issuer privKey
  metadataKey <- randomBytes 32
  Right () <- issuerSetMetadataKey issuer metadataKey

  -- Request 5 tokens
  Right request <- beginIssuance client 5

  Right (response, tokensIssued) <- issue issuer request 1 0 5
  assertBool "should issue multiple tokens" (tokensIssued > 0)

  Right (tokens, _keyIdx) <- finishIssuance client response
  assertBool "should get multiple tokens" (length tokens > 0)
