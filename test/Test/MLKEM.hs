{-# LANGUAGE OverloadedStrings #-}
module Test.MLKEM (tests) where

import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Test.Tasty
import Test.Tasty.HUnit

import Crypto.BoringSSL.MLKEM
import Crypto.BoringSSL.SecureBytes

tests :: TestTree
tests = testGroup "MLKEM"
  [ testGroup "ML-KEM-768"
    [ testCase "keygen produces correct sizes" $ do
        (pub, _priv) <- generateKeyPair MLKEM768
        BS.length (publicKeyToBytes pub) @?= publicKeyBytes MLKEM768

    , testCase "encap/decap round-trip" $ do
        (_pub, priv) <- generateKeyPair MLKEM768
        (ct, ssEncap) <- encapsulate priv
        BS.length ct @?= ciphertextBytes MLKEM768
        secureBytesLength ssEncap @?= sharedSecretBytes
        Right ssDecap <- pure $ decapsulate priv ct
        secureBytesToByteString ssDecap @?= secureBytesToByteString ssEncap

    , testCase "decap with wrong length ciphertext" $ do
        (_pub, priv) <- generateKeyPair MLKEM768
        assertBool "decapsulate should reject wrong-length ciphertext"
          (isLeft (decapsulate priv "short"))

    , testCase "different keypairs produce different shared secrets" $ do
        (_pub1, priv1) <- generateKeyPair MLKEM768
        (_pub2, priv2) <- generateKeyPair MLKEM768
        (ct1, ss1) <- encapsulate priv1
        (ct2, ss2) <- encapsulate priv2
        -- Different keys should produce different ciphertexts/secrets
        -- (with overwhelming probability)
        assertBool "different keypairs should differ"
          (secureBytesToByteString ss1 /= secureBytesToByteString ss2 || ct1 /= ct2)
    , testCase "wrong-key decapsulation implicitly rejects (pseudo-random secret)" $ do
        (_pub1, priv1) <- generateKeyPair MLKEM768
        (_pub2, priv2) <- generateKeyPair MLKEM768
        (ct, ssEncap) <- encapsulate priv1
        -- FIPS 203 implicit rejection: succeeds with a mismatching secret.
        Right ssWrong <- pure $ decapsulate priv2 ct
        assertBool "wrong-key decapsulation should produce different shared secret"
          (secureBytesToByteString ssWrong /= secureBytesToByteString ssEncap)
    , testCase "tampered ciphertext implicitly rejects (Right, mismatching secret)" $ do
        (pub, priv) <- generateKeyPair MLKEM768
        (ct, ssEncap) <- encapsulatePublic pub
        let tampered = BS.cons (BS.head ct + 1) (BS.tail ct)
        Right ssWrong <- pure $ decapsulate priv tampered
        assertBool "tampered ciphertext must yield a different secret, not an error"
          (secureBytesToByteString ssWrong /= secureBytesToByteString ssEncap)
    ]
  , testGroup "ML-KEM-768 encapsulatePublic"
    [ testCase "encapsulatePublic round-trip" $ do
        (pub, priv) <- generateKeyPair MLKEM768
        (ct, ssEncap) <- encapsulatePublic pub
        Right ssDecap <- pure $ decapsulate priv ct
        secureBytesToByteString ssDecap @?= secureBytesToByteString ssEncap
    , testCase "publicKeyFromBytes round-trips keygen output" $ do
        (pub, priv) <- generateKeyPair MLKEM768
        Right pub' <- pure $ publicKeyFromBytes MLKEM768 (publicKeyToBytes pub)
        pub' @?= pub
        (ct, ssEncap) <- encapsulatePublic pub'
        Right ssDecap <- pure $ decapsulate priv ct
        secureBytesToByteString ssDecap @?= secureBytesToByteString ssEncap
    , testCase "publicKeyFromBytes rejects wrong-length key" $
        assertBool "should reject wrong-length public key"
          (isLeft (publicKeyFromBytes MLKEM768 "short"))
    , testCase "publicKeyFromBytes rejects non-canonical bytes" $
        -- All-0xFF coefficients are out of range and must fail parsing.
        assertBool "should reject invalid encoding"
          (isLeft (publicKeyFromBytes MLKEM768 (BS.replicate (publicKeyBytes MLKEM768) 0xFF)))
    ]
  , testGroup "ML-KEM-1024"
    [ testCase "keygen produces correct sizes" $ do
        (pub, _priv) <- generateKeyPair MLKEM1024
        BS.length (publicKeyToBytes pub) @?= publicKeyBytes MLKEM1024

    , testCase "encap/decap round-trip" $ do
        (_pub, priv) <- generateKeyPair MLKEM1024
        (ct, ssEncap) <- encapsulate priv
        BS.length ct @?= ciphertextBytes MLKEM1024
        secureBytesLength ssEncap @?= sharedSecretBytes
        Right ssDecap <- pure $ decapsulate priv ct
        secureBytesToByteString ssDecap @?= secureBytesToByteString ssEncap

    , testCase "decap with wrong length ciphertext" $ do
        (_pub, priv) <- generateKeyPair MLKEM1024
        assertBool "decapsulate should reject wrong-length ciphertext"
          (isLeft (decapsulate priv "short"))

    , testCase "encapsulatePublic round-trip" $ do
        (pub, priv) <- generateKeyPair MLKEM1024
        (ct, ssEncap) <- encapsulatePublic pub
        Right ssDecap <- pure $ decapsulate priv ct
        secureBytesToByteString ssDecap @?= secureBytesToByteString ssEncap
    ]
  , testGroup "Constants"
    [ testCase "ML-KEM-768 public key bytes" $
        publicKeyBytes MLKEM768 @?= 1184
    , testCase "ML-KEM-768 ciphertext bytes" $
        ciphertextBytes MLKEM768 @?= 1088
    , testCase "ML-KEM-1024 public key bytes" $
        publicKeyBytes MLKEM1024 @?= 1568
    , testCase "ML-KEM-1024 ciphertext bytes" $
        ciphertextBytes MLKEM1024 @?= 1568
    , testCase "shared secret bytes" $
        sharedSecretBytes @?= 32
    ]
  ]
