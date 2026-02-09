{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Criterion.Main
import qualified Data.ByteString as BS
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BoringSSL.Digest (Algorithm(..), hash, hashSHA256)
import qualified Crypto.BoringSSL.AEAD as AEAD
import Crypto.BoringSSL.AEAD (AEADAlgorithm(..))
import qualified Crypto.BoringSSL.HMAC as HMAC
import qualified Crypto.BoringSSL.HKDF as HKDF
import qualified Crypto.BoringSSL.Ed25519 as Ed25519
import qualified Crypto.BoringSSL.X25519 as X25519
import qualified Crypto.BoringSSL.ECDSA as ECDSA
import Crypto.BoringSSL.ECDSA (ECCurve(..))
import qualified Crypto.BoringSSL.RSA as RSA
import qualified Crypto.BoringSSL.HPKE as HPKE
import qualified Crypto.BoringSSL.SPAKE2 as SPAKE2
import qualified Crypto.BoringSSL.Random as Random

-- | Extract Right or fail with an error message (pure, for unsafePerformIO).
unsafeUnwrap :: String -> Either a b -> b
unsafeUnwrap _ (Right x) = x
unsafeUnwrap label (Left _) = error ("bench setup failed: " ++ label)

-- Pre-generated keys (using unsafePerformIO at top level with NOINLINE)

{-# NOINLINE ed25519Priv #-}
ed25519Priv :: Ed25519.PrivateKey
ed25519Priv = snd (unsafePerformIO Ed25519.generateKeyPair)

{-# NOINLINE ed25519Pub #-}
ed25519Pub :: Ed25519.PublicKey
ed25519Pub = fst (unsafePerformIO Ed25519.generateKeyPair)

{-# NOINLINE x25519PrivA #-}
x25519PrivA :: X25519.PrivateKey
x25519PrivA = snd (unsafePerformIO X25519.generateKeyPair)

{-# NOINLINE x25519PubB #-}
x25519PubB :: X25519.PublicKey
x25519PubB = fst (unsafePerformIO X25519.generateKeyPair)

{-# NOINLINE ecdsaKeyPair #-}
ecdsaKeyPair :: ECDSA.ECKeyPair
ecdsaKeyPair = unsafePerformIO $ unsafeUnwrap "ECDSA keygen" <$> ECDSA.generateKeyPair P256

{-# NOINLINE ecdsaPubKey #-}
ecdsaPubKey :: ECDSA.ECPublicKey
ecdsaPubKey = unsafePerformIO $ unsafeUnwrap "ECDSA pubkey" <$> ECDSA.ecPublicKeyOfPair ecdsaKeyPair

{-# NOINLINE rsaKeyPair #-}
rsaKeyPair :: RSA.RSAKeyPair
rsaKeyPair = unsafePerformIO $ unsafeUnwrap "RSA keygen" <$> RSA.generateRSAKeyPair 2048

{-# NOINLINE rsaPubKey #-}
rsaPubKey :: RSA.RSAPublicKey
rsaPubKey = unsafePerformIO $ do
  pubBytes <- unsafeUnwrap "RSA pubkey bytes" <$> RSA.publicKeyToBytes rsaKeyPair
  unsafeUnwrap "RSA pubkey parse" <$> RSA.publicKeyFromBytes pubBytes

{-# NOINLINE aesGcmCtx #-}
aesGcmCtx :: AEAD.AEADCtx
aesGcmCtx = unsafePerformIO $ do
  key <- Random.randomBytes (AEAD.keyLength AES256GCM)
  unsafeUnwrap "AES-GCM ctx" <$> AEAD.newAEADCtx AES256GCM key

{-# NOINLINE chachaCtx #-}
chachaCtx :: AEAD.AEADCtx
chachaCtx = unsafePerformIO $ do
  key <- Random.randomBytes (AEAD.keyLength AEAD.ChaCha20Poly1305)
  unsafeUnwrap "ChaCha ctx" <$> AEAD.newAEADCtx AEAD.ChaCha20Poly1305 key

{-# NOINLINE hpkeRecipKey #-}
hpkeRecipKey :: HPKE.HPKEKey
hpkeRecipKey = unsafePerformIO $ unsafeUnwrap "HPKE keygen" <$> HPKE.generateKey HPKE.X25519HkdfSha256

{-# NOINLINE hpkeRecipPub #-}
hpkeRecipPub :: BS.ByteString
hpkeRecipPub = unsafePerformIO $ unsafeUnwrap "HPKE pubkey" <$> HPKE.publicKeyBytes hpkeRecipKey

input1KB :: BS.ByteString
input1KB = BS.replicate 1024 0x42

input64KB :: BS.ByteString
input64KB = BS.replicate (64 * 1024) 0x42

-- | Extract Right or fail with an error message.
unwrapRight :: String -> Either a b -> IO b
unwrapRight _     (Right x) = return x
unwrapRight label (Left _)  = fail ("bench setup failed: " ++ label)

main :: IO ()
main = do
  -- Pre-generate some nonces
  aeadNonce <- Random.randomBytes (AEAD.nonceLength AES256GCM)
  chachaNonce <- Random.randomBytes (AEAD.nonceLength AEAD.ChaCha20Poly1305)

  -- Pre-seal for open benchmarks
  aesCt <- unwrapRight "AES seal" =<< AEAD.seal aesGcmCtx aeadNonce input1KB ""
  chachaCt <- unwrapRight "ChaCha seal" =<< AEAD.seal chachaCtx chachaNonce input1KB ""

  -- Pre-sign for verify benchmarks
  let digest256 = hashSHA256 input1KB
  ecdsaSig <- unwrapRight "ECDSA sign" =<< ECDSA.ecdsaSign ecdsaKeyPair digest256
  rsaSig <- unwrapRight "RSA sign" =<< RSA.rsaSign rsaKeyPair SHA256 digest256

  -- Pre-encrypt for RSA decrypt benchmark
  rsaCt <- unwrapRight "RSA encrypt" =<< RSA.rsaEncrypt rsaPubKey "short plaintext"

  defaultMain
    [ bgroup "Digest"
      [ bench "SHA-256 1KB"    $ nf (hash SHA256) input1KB
      , bench "SHA-256 64KB"   $ nf (hash SHA256) input64KB
      , bench "SHA-512 1KB"    $ nf (hash SHA512) input1KB
      , bench "SHA-512 64KB"   $ nf (hash SHA512) input64KB
      , bench "BLAKE2b-256 1KB" $ nf (hash BLAKE2b256) input1KB
      , bench "BLAKE2b-256 64KB" $ nf (hash BLAKE2b256) input64KB
      ]
    , bgroup "AEAD"
      [ bench "AES-256-GCM seal 1KB" $ nfIO $ unwrapRight "s" =<< AEAD.seal aesGcmCtx aeadNonce input1KB ""
      , bench "AES-256-GCM open 1KB" $ nfIO $ unwrapRight "o" =<< AEAD.open aesGcmCtx aeadNonce aesCt ""
      , bench "ChaCha20-Poly1305 seal 1KB" $ nfIO $ unwrapRight "s" =<< AEAD.seal chachaCtx chachaNonce input1KB ""
      , bench "ChaCha20-Poly1305 open 1KB" $ nfIO $ unwrapRight "o" =<< AEAD.open chachaCtx chachaNonce chachaCt ""
      ]
    , bgroup "HMAC"
      [ bench "HMAC-SHA-256 1KB" $ nf (unsafeUnwrap "hmac" . HMAC.hmac SHA256 "key") input1KB
      ]
    , bgroup "HKDF"
      [ bench "HKDF-SHA-256 32B output" $ nf (\s -> unsafeUnwrap "hkdf" $ HKDF.hkdf SHA256 s "salt" "info" 32) "secret"
      ]
    , bgroup "Ed25519"
      [ bench "generateKeyPair" $ nfIO (Ed25519.generateKeyPair >>= \(p, _) -> return (Ed25519.publicKeyToBytes p))
      , bench "sign 1KB" $ nf (\m -> case Ed25519.sign ed25519Priv m of Right s -> Ed25519.signatureToBytes s; Left _ -> error "sign") input1KB
      , bench "verify 1KB" $ nf (\sig -> Ed25519.verify ed25519Pub input1KB sig) (unsafeUnwrap "sign" $ Ed25519.sign ed25519Priv input1KB)
      ]
    , bgroup "X25519"
      [ bench "generateKeyPair" $ nfIO (X25519.generateKeyPair >>= \(p, _) -> return (X25519.publicKeyToBytes p))
      , bench "sharedSecret" $ nf (\pk -> unsafeUnwrap "x25519" $ X25519.computeSharedSecret x25519PrivA pk) x25519PubB
      ]
    , bgroup "ECDSA"
      [ bench "P-256 sign" $ nfIO $ unwrapRight "s" =<< ECDSA.ecdsaSign ecdsaKeyPair digest256
      , bench "P-256 verify" $ nfIO $ unwrapRight "v" =<< ECDSA.ecdsaVerify ecdsaPubKey digest256 ecdsaSig
      ]
    , bgroup "RSA"
      [ bench "2048-bit sign (PKCS#1)" $ nfIO $ unwrapRight "s" =<< RSA.rsaSign rsaKeyPair SHA256 digest256
      , bench "2048-bit verify (PKCS#1)" $ nfIO $ unwrapRight "v" =<< RSA.rsaVerify rsaPubKey SHA256 digest256 rsaSig
      , bench "2048-bit encrypt (OAEP)" $ nfIO $ unwrapRight "e" =<< RSA.rsaEncrypt rsaPubKey "short plaintext"
      , bench "2048-bit decrypt (OAEP)" $ nfIO $ unwrapRight "d" =<< RSA.rsaDecrypt rsaKeyPair rsaCt
      ]
    , bgroup "HPKE"
      [ bench "X25519 setup+seal" $ nfIO $ do
          (_, sCtx) <- unwrapRight "s" =<< HPKE.setupSender HPKE.X25519HkdfSha256 HPKE.HkdfSha256
                          HPKE.Aes128Gcm hpkeRecipPub "bench"
          unwrapRight "s" =<< HPKE.senderSeal sCtx input1KB ""
      , bench "X25519 setup+open" $ nfIO $ do
          -- HPKE contexts are stateful (sequence number), so we must create
          -- a fresh sender+recipient pair for each iteration.
          (enc', sCtx') <- unwrapRight "s" =<< HPKE.setupSender HPKE.X25519HkdfSha256 HPKE.HkdfSha256
                              HPKE.Aes128Gcm hpkeRecipPub "bench"
          ct' <- unwrapRight "s" =<< HPKE.senderSeal sCtx' input1KB ""
          rCtx' <- unwrapRight "r" =<< HPKE.setupRecipient hpkeRecipKey HPKE.HkdfSha256
                      HPKE.Aes128Gcm enc' "bench"
          unwrapRight "o" =<< HPKE.recipientOpen rCtx' ct' ""
      ]
    , bgroup "SPAKE2"
      [ bench "full protocol" $ nfIO $ do
          ctxA <- unwrapRight "s" =<< SPAKE2.newContext SPAKE2.Alice "a" "b"
          ctxB <- unwrapRight "s" =<< SPAKE2.newContext SPAKE2.Bob   "b" "a"
          msgA <- unwrapRight "s" =<< SPAKE2.generateMessage ctxA "password"
          msgB <- unwrapRight "s" =<< SPAKE2.generateMessage ctxB "password"
          _ <- unwrapRight "s" =<< SPAKE2.processMessage ctxA msgB
          unwrapRight "s" =<< SPAKE2.processMessage ctxB msgA
      ]
    ]
