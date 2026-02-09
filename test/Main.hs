module Main (main) where

import Test.Tasty
import qualified Test.Digest
import qualified Test.AEAD

main :: IO ()
main = defaultMain $ testGroup "BoringSSL"
  [ Test.Digest.tests
  , Test.AEAD.tests
  ]
