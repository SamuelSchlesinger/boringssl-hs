{-# LANGUAGE OverloadedStrings #-}
module Test.Ed25519 (tests) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.Ed25519

hex :: BS.ByteString -> BS.ByteString
hex s = case Base16.decode s of
  Right bs -> bs
  Left err -> error ("bad hex literal: " ++ err)

-- | Extract Right or fail the test.
unwrap :: Show e => Either e a -> IO a
unwrap (Right x) = return x
unwrap (Left err) = assertFailure ("unexpected error: " ++ show err) >> error "unreachable"

tests :: TestTree
tests = testGroup "Ed25519"
  [ testCase "sign/verify round-trip" $ do
      (pub, priv) <- generateKeyPair
      let msg = "Hello, Ed25519!"
      sig <- unwrap $ sign priv msg
      assertBool "signature should verify" (verify pub msg sig)
  , testCase "invalid signature rejected" $ do
      (pub, priv) <- generateKeyPair
      let msg = "Hello, Ed25519!"
      sig <- unwrap $ sign priv msg
      let sigBytes = signatureToBytes sig
      case signatureFromBytes (BS.replicate (BS.length sigBytes) 0x00) of
        Nothing -> assertFailure "signatureFromBytes returned Nothing for 64 zero bytes"
        Just badSig -> assertBool "bad signature should not verify" (not (verify pub msg badSig))
  , testCase "wrong message rejected" $ do
      (pub, priv) <- generateKeyPair
      sig <- unwrap $ sign priv "message A"
      assertBool "wrong message should not verify" (not (verify pub "message B" sig))
  , testCase "keyPairFromSeed is deterministic" $ do
      let seed = BS.replicate 32 0x42
      (pub1, priv1) <- unwrap $ keyPairFromSeed seed
      (pub2, priv2) <- unwrap $ keyPairFromSeed seed
      pub1 @?= pub2
      priv1 @?= priv2
  , testCase "keyPairFromSeed sign/verify" $ do
      let seed = BS.replicate 32 0xAB
      (pub, priv) <- unwrap $ keyPairFromSeed seed
      let msg = "deterministic test"
      sig <- unwrap $ sign priv msg
      assertBool "signature should verify" (verify pub msg sig)
  , testCase "keyPairFromSeed rejects wrong seed length" $ do
      case keyPairFromSeed (BS.replicate 31 0x42) of
        Left _ -> return ()
        Right _ -> assertFailure "should reject 31-byte seed"
      case keyPairFromSeed (BS.replicate 33 0x42) of
        Left _ -> return ()
        Right _ -> assertFailure "should reject 33-byte seed"
      case keyPairFromSeed BS.empty of
        Left _ -> return ()
        Right _ -> assertFailure "should reject empty seed"
  , testCase "generateKeyPair produces unique keys" $ do
      (pub1, _) <- generateKeyPair
      (pub2, _) <- generateKeyPair
      assertBool "two key pairs should differ" (pub1 /= pub2)
  , testCase "sign is deterministic" $ do
      (_, priv) <- generateKeyPair
      let msg = "determinism test"
      sig1 <- unwrap $ sign priv msg
      sig2 <- unwrap $ sign priv msg
      sig1 @?= sig2
  , testCase "key sizes from generateKeyPair" $ do
      (pub, priv) <- generateKeyPair
      BS.length (publicKeyToBytes pub) @?= 32
      BS.length (privateKeyToBytes priv) @?= 64
  , testCase "signature size is 64 bytes" $ do
      (_, priv) <- generateKeyPair
      sig <- unwrap $ sign priv "test"
      BS.length (signatureToBytes sig) @?= 64
  , testCase "RFC 8032 Section 7.1 test vector 1" $ do
      let seed = hex "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
          expectedPub = hex "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
          expectedSig = hex "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
      (pub, priv) <- unwrap $ keyPairFromSeed seed
      publicKeyToBytes pub @?= expectedPub
      sig <- unwrap $ sign priv BS.empty
      signatureToBytes sig @?= expectedSig
      assertBool "signature should verify" (verify pub BS.empty sig)
  , testCase "RFC 8032 Section 7.1 test vector 2" $ do
      let seed = hex "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
          expectedPub = hex "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
          expectedSig = hex "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
          msg = hex "72"
      (pub, priv) <- unwrap $ keyPairFromSeed seed
      publicKeyToBytes pub @?= expectedPub
      sig <- unwrap $ sign priv msg
      signatureToBytes sig @?= expectedSig
      assertBool "signature should verify" (verify pub msg sig)
  , testCase "RFC 8032 Section 7.1 test vector 3" $ do
      let seed = hex "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
          expectedPub = hex "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
          expectedSig = hex "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
          msg = hex "af82"
      (pub, priv) <- unwrap $ keyPairFromSeed seed
      publicKeyToBytes pub @?= expectedPub
      sig <- unwrap $ sign priv msg
      signatureToBytes sig @?= expectedSig
      assertBool "signature should verify" (verify pub msg sig)
  , testCase "RFC 8032 Section 7.1 test vector 5" $ do
      let seed = hex "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
          expectedPub = hex "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
          expectedSig = hex "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
          msg = hex "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
      (pub, priv) <- unwrap $ keyPairFromSeed seed
      publicKeyToBytes pub @?= expectedPub
      sig <- unwrap $ sign priv msg
      signatureToBytes sig @?= expectedSig
      assertBool "signature should verify" (verify pub msg sig)
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
    , testCase "privateKeyFromBytes accepts 64 bytes" $ do
        let bs = BS.replicate 64 0x42
        case privateKeyFromBytes bs of
          Just _  -> return ()
          Nothing -> assertFailure "privateKeyFromBytes rejected valid 64-byte input"
    , testCase "privateKeyFromBytes rejects wrong lengths" $ do
        assertBool "should reject 0 bytes" (privateKeyFromBytes BS.empty == Nothing)
        assertBool "should reject 63 bytes" (privateKeyFromBytes (BS.replicate 63 0x00) == Nothing)
        assertBool "should reject 65 bytes" (privateKeyFromBytes (BS.replicate 65 0x00) == Nothing)
    , testCase "signatureFromBytes accepts 64 bytes" $ do
        let bs = BS.replicate 64 0x42
        case signatureFromBytes bs of
          Just _  -> return ()
          Nothing -> assertFailure "signatureFromBytes rejected valid 64-byte input"
    , testCase "signatureFromBytes rejects wrong lengths" $ do
        assertBool "should reject 0 bytes" (signatureFromBytes BS.empty == Nothing)
        assertBool "should reject 63 bytes" (signatureFromBytes (BS.replicate 63 0x00) == Nothing)
        assertBool "should reject 65 bytes" (signatureFromBytes (BS.replicate 65 0x00) == Nothing)
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
    , testCase "signatureToBytes round-trip" $ do
        (_, priv) <- generateKeyPair
        sig <- unwrap $ sign priv "test"
        case signatureFromBytes (signatureToBytes sig) of
          Just sig' -> sig' @?= sig
          Nothing   -> assertFailure "signatureFromBytes rejected signatureToBytes output"
    ]
  ]
