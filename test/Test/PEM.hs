{-# LANGUAGE OverloadedStrings #-}
module Test.PEM (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.PEM

-- | Extract Right or fail the test.
unwrap :: Show e => Either e a -> IO a
unwrap (Right x) = return x
unwrap (Left err) = assertFailure ("unexpected error: " ++ show err) >> error "unreachable"

tests :: TestTree
tests = testGroup "PEM"
  [ testCase "encode/decode round-trip" $ do
      let label = "CERTIFICATE"
          der = BS8.pack "some binary data here \x00\x01\x02\xff"
      pem <- unwrap $ pemEncode label der
      case pemDecode pem of
        Left err -> assertFailure ("pemDecode failed on pemEncode output: " ++ show err)
        Right (decodedLabel, decodedDer) -> do
          decodedLabel @?= label
          decodedDer @?= der

  , testCase "encode/decode round-trip with empty data" $ do
      let label = "EMPTY"
          der = BS.empty
      pem <- unwrap $ pemEncode label der
      case pemDecode pem of
        Left err -> assertFailure ("pemDecode failed on empty data: " ++ show err)
        Right (decodedLabel, decodedDer) -> do
          decodedLabel @?= label
          decodedDer @?= der

  , testCase "encode/decode with RSA PRIVATE KEY label" $ do
      let label = "RSA PRIVATE KEY"
          der = BS.replicate 128 0x42
      pem <- unwrap $ pemEncode label der
      case pemDecode pem of
        Left err -> assertFailure ("pemDecode failed: " ++ show err)
        Right (decodedLabel, decodedDer) -> do
          decodedLabel @?= label
          decodedDer @?= der

  , testCase "decode rejects garbage" $ do
      let result = pemDecode "not a pem"
      case result of
        Left _  -> return ()
        Right _ -> assertFailure "pemDecode should reject garbage"

  , testCase "decode rejects missing footer" $ do
      let incomplete = BS8.pack "-----BEGIN TEST-----\nYWJj\n"
      case pemDecode incomplete of
        Left _  -> return ()
        Right _ -> assertFailure "pemDecode should reject missing footer"

  , testCase "decode known PEM" $ do
      let pem = BS8.unlines
            [ "-----BEGIN TEST DATA-----"
            , "SGVsbG8sIFdvcmxkIQ=="
            , "-----END TEST DATA-----"
            ]
      case pemDecode pem of
        Left err -> assertFailure ("pemDecode failed on known PEM: " ++ show err)
        Right (label, decoded) -> do
          label @?= "TEST DATA"
          decoded @?= BS8.pack "Hello, World!"

  , testCase "encode produces correct header/footer" $ do
      pem <- unwrap $ pemEncode "MY TYPE" "data"
      assertBool "should start with BEGIN header"
        (BS8.isPrefixOf "-----BEGIN MY TYPE-----" pem)
      assertBool "should contain END footer"
        (BS8.isInfixOf "-----END MY TYPE-----" pem)

  , testGroup "pemDecodeMany"
    [ testCase "single block" $ do
        let pem = BS8.unlines
              [ "-----BEGIN TEST-----"
              , "SGVsbG8="
              , "-----END TEST-----"
              ]
        case pemDecodeMany pem of
          Left err -> assertFailure ("pemDecodeMany failed: " ++ show err)
          Right blocks -> do
            length blocks @?= 1
            fst (head blocks) @?= "TEST"
            snd (head blocks) @?= "Hello"
    , testCase "multiple blocks with different labels" $ do
        let pem = BS8.unlines
              [ "-----BEGIN CERTIFICATE-----"
              , "AQID"
              , "-----END CERTIFICATE-----"
              , "-----BEGIN RSA PRIVATE KEY-----"
              , "BAUG"
              , "-----END RSA PRIVATE KEY-----"
              ]
        case pemDecodeMany pem of
          Left err -> assertFailure ("pemDecodeMany failed: " ++ show err)
          Right blocks -> do
            length blocks @?= 2
            fst (head blocks) @?= "CERTIFICATE"
            fst (blocks !! 1) @?= "RSA PRIVATE KEY"
    , testCase "no blocks returns Left" $ do
        case pemDecodeMany "just some junk text" of
          Left _ -> return ()
          Right _ -> assertFailure "should return Left for no blocks"
    , testCase "junk between blocks is skipped" $ do
        let pem = BS8.unlines
              [ "some junk"
              , "-----BEGIN A-----"
              , "YQ=="
              , "-----END A-----"
              , "more junk"
              , "-----BEGIN B-----"
              , "Yg=="
              , "-----END B-----"
              ]
        case pemDecodeMany pem of
          Left err -> assertFailure ("pemDecodeMany failed: " ++ show err)
          Right blocks -> do
            length blocks @?= 2
            snd (head blocks) @?= "a"
            snd (blocks !! 1) @?= "b"
    ]
  , testCase "encode wraps lines at 64 characters" $ do
      let der = BS.replicate 100 0x41  -- 100 bytes of 'A'
      pem <- unwrap $ pemEncode "TEST" der
      let ls = BS8.lines pem
      -- Check that base64 lines (not header/footer) are at most 64 chars
      let bodyLines = filter (\l -> not (BS8.isPrefixOf "-----" l) && not (BS.null l)) ls
      mapM_ (\l -> assertBool ("line too long: " ++ show (BS.length l))
                               (BS.length l <= 64)) bodyLines
  ]
