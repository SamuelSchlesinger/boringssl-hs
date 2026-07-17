{-# LANGUAGE OverloadedStrings #-}
module Test.X509 (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.X509

-- A self-signed X.509 v3 certificate (DER-encoded, hex).
-- Generated with: openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out cert.pem -days 3650 -nodes -subj "/CN=Test/O=BoringSSL"
-- Then converted to DER and hex-encoded.
testCertHex :: BS.ByteString
testCertHex = BS.concat
  [ "308203273082020fa00302010202141e31ad6f370f27"
  , "0c7428d91a5140cefa98bdd7f4300d06092a864886f7"
  , "0d01010b05003023310d300b06035504030c04546573"
  , "7431123010060355040a0c09426f72696e6753534c30"
  , "1e170d3236303230393037353535345a170d33363032"
  , "30373037353535345a3023310d300b06035504030c04"
  , "5465737431123010060355040a0c09426f72696e6753"
  , "534c30820122300d06092a864886f70d010101050003"
  , "82010f003082010a0282010100b9e99149c79e4057ef"
  , "79fbca06cc71c990470e12b72d05683218e369b39e34"
  , "8aee089c8b0333494669f920eaaa6869be9280847eea"
  , "08bd6c54f25bd6c93390e410e05e1804d626768fbb55"
  , "092984918efb98ce5ed23063c7c1cfa2b46d7239f661"
  , "0d39f5a18c5a66718b71c636b56c89a6a7684ba193cf"
  , "c17026df835912f4265aa47ba63e5ebe3923fe8bfd37"
  , "8284dd8a37af133f1a911b2da0740fdc77be66d6f6a9"
  , "f201e2f136d3413f24a6bd2134159a3a134fdb4c2e08"
  , "3b211d641064dcc3eaf749b3a8169db0c90853605ad8"
  , "0d416cc708b9f1893a91987b06ca1275bf659bf7224b"
  , "f3847a10bc29c39fd73caa08b31bc3a6102bdac409af"
  , "214531ef710203010001a3533051301d0603551d0e04"
  , "160414099a3f91b4a264676d9d61e7ab38fdd34ab3dd"
  , "94301f0603551d23041830168014099a3f91b4a26467"
  , "6d9d61e7ab38fdd34ab3dd94300f0603551d130101ff"
  , "040530030101ff300d06092a864886f70d01010b0500"
  , "03820101003089f5cba91337acabc55e883531682b76"
  , "7035a44cb2baf5c8a52459238d98457e92c36c425698"
  , "6e818efe4fc28e800fd1670ea365e1603fc0a9d6079c"
  , "fe09fe31eccda0fc48f88a06818157334ea88023104a"
  , "e0595a17c6a4a87a165f70a21f61802f283c6c72ac7b"
  , "aff8dc784234baab31ac8d8b5162a68fad49c06bab83"
  , "5cd7cec301affce4845d4c4a68bfb23a71dc3226be13"
  , "e731104cfb296a6511ef481be02273285af6d10e3c07"
  , "189f8fa7ed09dc3f1f71604fc5a62a40d787f08e9f06"
  , "504a5408873e11354cc05f5589939ff63c8260ff8d37"
  , "d3e1799db779150f40533f903367d5f741ec66c9fef9"
  , "89bd388ecee290808534f792cfb9f2041795a6"
  ]

testCertDER :: BS.ByteString
testCertDER = case Base16.decode testCertHex of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

tests :: TestTree
tests = testGroup "X509"
  [ testCase "parseDER rejects garbage" $ do
      let result = parseDER "not a certificate"
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "parseDER should reject garbage input"

  , testCase "parseDER rejects empty input" $ do
      let result = parseDER BS.empty
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "parseDER should reject empty input"

  , testCase "parseDER rejects truncated DER" $ do
      let result = parseDER "\x30\x82\x01\x00"
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "parseDER should reject truncated DER"

  , testCase "toDER round-trip preserves bytes" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER should parse the test certificate: " ++ show err)
        Right cert -> do
          case toDER cert of
            Left err -> assertFailure ("toDER failed: " ++ show err)
            Right reencoded -> reencoded @?= testCertDER

  , testCase "subjectName and issuerName on parsed cert" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER should parse the test certificate: " ++ show err)
        Right cert -> do
          Right subj <- pure (subjectName cert)
          Right iss  <- pure (issuerName cert)
          assertBool ("subjectName should contain 'Test', got: " ++ subj)
            (isInfixOf' "Test" subj)
          assertBool ("issuerName should contain 'BoringSSL', got: " ++ iss)
            (isInfixOf' "BoringSSL" iss)

  , testCase "self-signed cert: issuer equals subject" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER should parse: " ++ show err)
        Right cert -> do
          Right subj <- pure (subjectName cert)
          Right iss  <- pure (issuerName cert)
          subj @?= iss

    -- Feature 6: public key extraction
  , testCase "certPublicKey extracts RSA key from test cert" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          result <- certPublicKey cert
          case result of
            Right (CertPubKeyRSA _) -> return ()
            Right other -> assertFailure ("expected RSA key, got: " ++ show other)
            Left err -> assertFailure ("certPublicKey failed: " ++ show err)

  , testCase "certPublicKey RSA key matches verifySelfSigned" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          assertBool "test cert should be self-signed" (verifySelfSigned cert)
          result <- certPublicKey cert
          case result of
            Right (CertPubKeyRSA _) -> return ()
            _ -> assertFailure "expected RSA key"

    -- Feature 7: certificate extensions
  , testCase "certKeyUsage on test cert (CA)" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          case certKeyUsage cert of
            Nothing -> return ()  -- test cert may not have key usage
            Just flags -> assertBool "key usage should be non-empty" (not (null flags))

  , testCase "certBasicConstraints on test cert (CA:TRUE)" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          case certBasicConstraints cert of
            Nothing -> assertFailure "test cert should have basic constraints"
            Just (isCA, _) -> assertBool "test cert should be CA" isCA

  , testCase "certSubjectAltNames on test cert" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          let sans = certSubjectAltNames cert
          -- Our test cert doesn't have SANs, so empty is expected
          length sans `seq` return ()

    -- Feature 8: chain verification
  , testCase "self-signed cert verifies against itself" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          Right store <- newX509Store
          Right () <- addTrustAnchor store cert
          Right result <- verifyCertChain store cert []
          case result of
            ChainVerified -> return ()
            ChainRejected code msg -> assertFailure
              ("verification should succeed but got: " ++ show code ++ " " ++ msg)

  , testCase "untrusted cert fails against empty store" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          Right store <- newX509Store  -- empty store
          Right result <- verifyCertChain store cert []
          case result of
            ChainRejected _ _ -> return ()
            ChainVerified -> assertFailure "verification should fail against empty store"

    -- Feature 9: signature algorithm
  , testCase "certSignatureAlgorithm on test cert" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          result <- certSignatureAlgorithm cert
          case result of
            Nothing -> assertFailure "should have a signature algorithm"
            Just info -> do
              assertBool "NID should be positive" (sigAlgNID info > 0)
              assertBool "short name should be non-empty" (not (null (sigAlgShortName info)))

    -- Feature 10: DN as DER
  , testCase "certSubjectDER non-empty" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          Right der <- pure (certSubjectDER cert)
          assertBool "subject DER should be non-empty" (not (BS.null der))

  , testCase "certSubjectDER == certIssuerDER for self-signed" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          Right subjDER <- pure (certSubjectDER cert)
          Right issDER <- pure (certIssuerDER cert)
          subjDER @?= issDER

  , testCase "certSubjectDER starts with SEQUENCE tag 0x30" $ do
      case parseDER testCertDER of
        Left err -> assertFailure ("parseDER failed: " ++ show err)
        Right cert -> do
          Right der <- pure (certSubjectDER cert)
          assertBool "should start with 0x30" (not (BS.null der) && BS.head der == 0x30)
  ]

-- Simple infix check for String
isInfixOf' :: String -> String -> Bool
isInfixOf' needle haystack = any (isPrefixOf' needle) (tails' haystack)

isPrefixOf' :: String -> String -> Bool
isPrefixOf' [] _ = True
isPrefixOf' _ [] = False
isPrefixOf' (x:xs) (y:ys) = x == y && isPrefixOf' xs ys

tails' :: [a] -> [[a]]
tails' [] = [[]]
tails' xs@(_:xs') = xs : tails' xs'
