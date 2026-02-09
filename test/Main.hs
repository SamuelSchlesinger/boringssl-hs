module Main (main) where

import Test.Tasty
import qualified Test.Digest
import qualified Test.AEAD
import qualified Test.HMAC
import qualified Test.HKDF
import qualified Test.Random
import qualified Test.Cipher
import qualified Test.Ed25519
import qualified Test.X25519
import qualified Test.ECDSA
import qualified Test.ECDH
import qualified Test.RSA
import qualified Test.Base64
import qualified Test.PBKDF2
import qualified Test.MLKEM
import qualified Test.MLDSA
import qualified Test.X509
import qualified Test.PEM
import qualified Test.HPKE
import qualified Test.SPAKE2
import qualified Test.TrustToken
import qualified Test.Properties

main :: IO ()
main = defaultMain $ testGroup "BoringSSL"
  [ Test.Digest.tests
  , Test.AEAD.tests
  , Test.HMAC.tests
  , Test.HKDF.tests
  , Test.Random.tests
  , Test.Cipher.tests
  , Test.Ed25519.tests
  , Test.X25519.tests
  , Test.ECDSA.tests
  , Test.ECDH.tests
  , Test.RSA.tests
  , Test.Base64.tests
  , Test.PBKDF2.tests
  , Test.MLKEM.tests
  , Test.MLDSA.tests
  , Test.X509.tests
  , Test.PEM.tests
  , Test.HPKE.tests
  , Test.SPAKE2.tests
  , Test.TrustToken.tests
  , Test.Properties.tests
  ]
