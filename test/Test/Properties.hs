{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Test.Properties (tests) where

import Test.Tasty
import Test.Tasty.QuickCheck

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

import qualified Crypto.BoringSSL.Digest as Digest
import Crypto.BoringSSL.Digest (Algorithm(..))
import qualified Crypto.BoringSSL.AEAD as AEAD
import Crypto.BoringSSL.AEAD (AEADAlgorithm(..))
import qualified Crypto.BoringSSL.HMAC as HMAC
import qualified Crypto.BoringSSL.HKDF as HKDF
import qualified Crypto.BoringSSL.Random as Random
import qualified Crypto.BoringSSL.Cipher as Cipher
import Crypto.BoringSSL.Cipher (CipherAlgorithm(..))
import qualified Crypto.BoringSSL.Ed25519 as Ed25519
import qualified Crypto.BoringSSL.X25519 as X25519
import qualified Crypto.BoringSSL.ECDSA as ECDSA
import Crypto.BoringSSL.ECDSA (ECCurve(..))
import qualified Crypto.BoringSSL.ECDH as ECDH
import qualified Crypto.BoringSSL.RSA as RSA
import qualified Crypto.BoringSSL.Base64 as Base64
import qualified Crypto.BoringSSL.SecureBytes as SB

-- ---------------------------------------------------------------------------
-- Arbitrary instances
-- ---------------------------------------------------------------------------

newtype ArbitraryBS = ArbitraryBS { unABS :: ByteString }
  deriving (Show, Eq)

instance Arbitrary ArbitraryBS where
  arbitrary = ArbitraryBS . BS.pack <$> arbitrary
  shrink (ArbitraryBS bs) =
    [ ArbitraryBS (BS.pack w8s) | w8s <- shrink (BS.unpack bs) ]

-- Non-empty ByteString
newtype NonEmptyBS = NonEmptyBS { unNEBS :: ByteString }
  deriving (Show, Eq)

instance Arbitrary NonEmptyBS where
  arbitrary = do
    w8s <- listOf1 arbitrary
    return $ NonEmptyBS (BS.pack w8s)
  shrink (NonEmptyBS bs)
    | BS.length bs <= 1 = []
    | otherwise =
        [ NonEmptyBS (BS.pack w8s)
        | w8s <- shrink (BS.unpack bs), not (null w8s) ]

instance Arbitrary Algorithm where
  arbitrary = elements [SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_256, MD5, BLAKE2b256]

instance Arbitrary AEADAlgorithm where
  arbitrary = elements
    [ AES128GCM, AES192GCM, AES256GCM
    , ChaCha20Poly1305, XChaCha20Poly1305
    , AES128GCMSIV, AES256GCMSIV
    , AES128CtrHmacSha256, AES256CtrHmacSha256
    , AES128EAX, AES256EAX
    , AES128CCMBluetooth, AES128CCMBluetooth8, AES128CCMMatter
    ]

instance Arbitrary CipherAlgorithm where
  arbitrary = elements [AES128CBC, AES256CBC, AES128CTR, AES256CTR, AES128ECB, AES256ECB, AES128OFB, AES256OFB]

instance Arbitrary ECCurve where
  arbitrary = elements [P256, P384, P521]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

genBytes :: Int -> Gen ByteString
genBytes n = BS.pack <$> vectorOf n arbitrary

-- | Split a ByteString into random-sized chunks.
splitIntoChunks :: ByteString -> Gen [ByteString]
splitIntoChunks bs
  | BS.null bs = return [BS.empty]
  | otherwise = do
      n <- choose (1, BS.length bs)
      let (chunk, rest) = BS.splitAt n bs
      if BS.null rest
        then return [chunk]
        else do
          restChunks <- splitIntoChunks rest
          return (chunk : restChunks)

-- | Flip the first byte of a ByteString using XOR.
flipFirstByte :: ByteString -> ByteString
flipFirstByte bs
  | BS.null bs = bs
  | otherwise =
      let b = BS.head bs
      in BS.cons (b `xor` (1 :: Word8)) (BS.tail bs)

-- ---------------------------------------------------------------------------
-- Pre-generated RSA key pair (to avoid slow keygen in every property)
-- ---------------------------------------------------------------------------

{-# NOINLINE rsaKeyPair #-}
rsaKeyPair :: RSA.RSAKeyPair
rsaKeyPair = unsafePerformIO $ do
  Right kp <- RSA.generateRSAKeyPair 2048
  return kp

{-# NOINLINE rsaPubKey #-}
rsaPubKey :: RSA.RSAPublicKey
rsaPubKey = unsafePerformIO $ do
  Right pubBytes <- RSA.publicKeyToBytes rsaKeyPair
  Right pub <- RSA.publicKeyFromBytes pubBytes
  return pub

-- ---------------------------------------------------------------------------
-- Digest Properties
-- ---------------------------------------------------------------------------

digestProperties :: TestTree
digestProperties = testGroup "Digest"
  [ testProperty "hash is deterministic" $
      prop_hashDeterministic
  , testProperty "hash output length matches digestSize" $
      prop_hashLength
  , testProperty "different inputs produce different hashes" $
      prop_hashDifferentInputs
  , testProperty "streaming matches one-shot" $
      prop_streamingMatchesOneShot
  , testProperty "chunked streaming matches one-shot" $
      prop_streamingChunked
  ]

prop_hashDeterministic :: Algorithm -> ArbitraryBS -> Bool
prop_hashDeterministic algo (ArbitraryBS bs) =
  Digest.hash algo bs == Digest.hash algo bs

prop_hashLength :: Algorithm -> ArbitraryBS -> Bool
prop_hashLength algo (ArbitraryBS bs) =
  BS.length (Digest.hash algo bs) == Digest.digestSize algo

prop_hashDifferentInputs :: Algorithm -> NonEmptyBS -> NonEmptyBS -> Property
prop_hashDifferentInputs algo (NonEmptyBS a) (NonEmptyBS b) =
  a /= b ==> Digest.hash algo a /= Digest.hash algo b

prop_streamingMatchesOneShot :: Algorithm -> ArbitraryBS -> Property
prop_streamingMatchesOneShot algo (ArbitraryBS bs) = ioProperty $ do
  Right ctx <- Digest.digestInit algo
  Right () <- Digest.digestUpdate ctx bs
  Right streamResult <- Digest.digestFinalize ctx
  let oneShotResult = Digest.hash algo bs
  return (streamResult === oneShotResult)

prop_streamingChunked :: Algorithm -> ArbitraryBS -> Property
prop_streamingChunked algo (ArbitraryBS bs) =
  forAll (splitIntoChunks bs) $ \chunks ->
    ioProperty $ do
      Right ctx <- Digest.digestInit algo
      mapM_ (\chunk -> do Right () <- Digest.digestUpdate ctx chunk; return ()) chunks
      Right streamResult <- Digest.digestFinalize ctx
      let oneShotResult = Digest.hash algo bs
      return (streamResult === oneShotResult)

-- ---------------------------------------------------------------------------
-- AEAD Properties
-- ---------------------------------------------------------------------------

aeadProperties :: TestTree
aeadProperties = testGroup "AEAD"
  [ testProperty "seal then open recovers plaintext" $
      prop_aeadRoundTrip
  , testProperty "modifying ciphertext causes open to fail" $
      prop_aeadAuthFailure
  , testProperty "different nonces produce different ciphertexts" $
      prop_aeadDifferentNonce
  , testProperty "changing AD causes open to fail" $
      prop_aeadAAD
  ]

prop_aeadRoundTrip :: AEADAlgorithm -> ArbitraryBS -> ArbitraryBS -> Property
prop_aeadRoundTrip algo (ArbitraryBS plaintext) (ArbitraryBS ad) = ioProperty $ do
  key <- Random.randomBytes (AEAD.keyLength algo)
  nonce <- Random.randomBytes (AEAD.nonceLength algo)
  Right ctx <- AEAD.newAEADCtx algo key
  sealResult <- pure $ AEAD.seal ctx nonce plaintext ad
  case sealResult of
    Left err -> return $ counterexample ("seal failed: " ++ show err) False
    Right ct -> do
      openResult <- pure $ AEAD.open ctx nonce ct ad
      case openResult of
        Left err -> return $ counterexample ("open failed: " ++ show err) False
        Right pt -> return $ pt === plaintext

prop_aeadAuthFailure :: AEADAlgorithm -> ArbitraryBS -> ArbitraryBS -> Property
prop_aeadAuthFailure algo (ArbitraryBS plaintext) (ArbitraryBS ad) = ioProperty $ do
  key <- Random.randomBytes (AEAD.keyLength algo)
  nonce <- Random.randomBytes (AEAD.nonceLength algo)
  Right ctx <- AEAD.newAEADCtx algo key
  sealResult <- pure $ AEAD.seal ctx nonce plaintext ad
  case sealResult of
    Left _ -> return $ property True  -- seal failed, skip
    Right ct -> do
      if BS.null ct
        then return $ property True
        else do
          let tampered = flipFirstByte ct
          openResult <- pure $ AEAD.open ctx nonce tampered ad
          case openResult of
            Left _  -> return $ property True
            Right _ -> return $
              counterexample "open should have failed with tampered ciphertext" False

prop_aeadDifferentNonce :: AEADAlgorithm -> NonEmptyBS -> ArbitraryBS -> Property
prop_aeadDifferentNonce algo (NonEmptyBS plaintext) (ArbitraryBS ad) = ioProperty $ do
  key <- Random.randomBytes (AEAD.keyLength algo)
  nonce1 <- Random.randomBytes (AEAD.nonceLength algo)
  nonce2 <- Random.randomBytes (AEAD.nonceLength algo)
  if nonce1 == nonce2
    then return $ property True  -- extremely unlikely, skip
    else do
      Right ctx <- AEAD.newAEADCtx algo key
      r1 <- pure $ AEAD.seal ctx nonce1 plaintext ad
      r2 <- pure $ AEAD.seal ctx nonce2 plaintext ad
      case (r1, r2) of
        (Right ct1, Right ct2) ->
          return $ counterexample "same ciphertext with different nonces" (ct1 /= ct2)
        _ -> return $ property True

prop_aeadAAD :: AEADAlgorithm -> ArbitraryBS -> Property
prop_aeadAAD algo (ArbitraryBS plaintext) = ioProperty $ do
  key <- Random.randomBytes (AEAD.keyLength algo)
  nonce <- Random.randomBytes (AEAD.nonceLength algo)
  Right ctx <- AEAD.newAEADCtx algo key
  let ad1 = BS.pack [1, 2, 3]
      ad2 = BS.pack [4, 5, 6]
  sealResult <- pure $ AEAD.seal ctx nonce plaintext ad1
  case sealResult of
    Left _ -> return $ property True
    Right ct -> do
      openResult <- pure $ AEAD.open ctx nonce ct ad2
      case openResult of
        Left _  -> return $ property True
        Right _ -> return $
          counterexample "open should have failed with wrong AD" False

-- ---------------------------------------------------------------------------
-- HMAC Properties
-- ---------------------------------------------------------------------------

hmacProperties :: TestTree
hmacProperties = testGroup "HMAC"
  [ testProperty "hmac is deterministic" $
      prop_hmacDeterministic
  , testProperty "hmac output length matches digest size" $
      prop_hmacLength
  , testProperty "streaming matches one-shot" $
      prop_hmacStreamingMatchesOneShot
  , testProperty "different keys produce different MACs" $
      prop_hmacDifferentKeys
  ]

prop_hmacDeterministic :: Algorithm -> ArbitraryBS -> ArbitraryBS -> Bool
prop_hmacDeterministic algo (ArbitraryBS key) (ArbitraryBS msg) =
  HMAC.hmac algo key msg == HMAC.hmac algo key msg

prop_hmacLength :: Algorithm -> ArbitraryBS -> ArbitraryBS -> Property
prop_hmacLength algo (ArbitraryBS key) (ArbitraryBS msg) =
  BS.length (HMAC.hmac algo key msg) === Digest.digestSize algo

prop_hmacStreamingMatchesOneShot :: Algorithm -> ArbitraryBS -> ArbitraryBS -> Property
prop_hmacStreamingMatchesOneShot algo (ArbitraryBS key) (ArbitraryBS msg) = ioProperty $ do
  eCtx <- HMAC.hmacInit algo key
  case eCtx of
    Left err -> return $ counterexample ("hmacInit failed: " ++ show err) False
    Right ctx -> do
      eUpd <- HMAC.hmacUpdate ctx msg
      case eUpd of
        Left err -> return $ counterexample ("hmacUpdate failed: " ++ show err) False
        Right () -> do
          eResult <- HMAC.hmacFinalize ctx
          case eResult of
            Left err -> return $ counterexample ("hmacFinalize failed: " ++ show err) False
            Right streamResult -> return (streamResult === HMAC.hmac algo key msg)

prop_hmacDifferentKeys :: Algorithm -> NonEmptyBS -> Property
prop_hmacDifferentKeys algo (NonEmptyBS msg) = ioProperty $ do
  key1 <- Random.randomBytes 32
  key2 <- Random.randomBytes 32
  if key1 == key2
    then return $ property True
    else return $ counterexample "same HMAC with different keys"
                    (HMAC.hmac algo key1 msg /= HMAC.hmac algo key2 msg)

-- ---------------------------------------------------------------------------
-- HKDF Properties
-- ---------------------------------------------------------------------------

hkdfProperties :: TestTree
hkdfProperties = testGroup "HKDF"
  [ testProperty "hkdf is deterministic" $
      prop_hkdfDeterministic
  , testProperty "hkdf output has requested length" $
      prop_hkdfLength
  , testProperty "extract then expand matches full hkdf" $
      prop_hkdfExtractExpandMatchesFull
  ]

prop_hkdfDeterministic :: ArbitraryBS -> ArbitraryBS -> ArbitraryBS -> Property
prop_hkdfDeterministic (ArbitraryBS secret) (ArbitraryBS salt) (ArbitraryBS info) =
  let outLen = 32
      r1 = fmap SB.secureBytesToByteString $ HKDF.hkdf SHA256 secret salt info outLen
      r2 = fmap SB.secureBytesToByteString $ HKDF.hkdf SHA256 secret salt info outLen
  in r1 === r2

prop_hkdfLength :: Algorithm -> ArbitraryBS -> ArbitraryBS -> ArbitraryBS -> Property
prop_hkdfLength algo (ArbitraryBS secret) (ArbitraryBS salt) (ArbitraryBS info) =
  let maxOut = 255 * Digest.digestSize algo
      outLen = min 64 maxOut
  in outLen > 0 ==>
     case HKDF.hkdf algo secret salt info outLen of
       Right sb -> SB.secureBytesLength sb == outLen
       Left _   -> False

prop_hkdfExtractExpandMatchesFull :: Algorithm -> ArbitraryBS -> ArbitraryBS -> ArbitraryBS -> Property
prop_hkdfExtractExpandMatchesFull algo (ArbitraryBS secret) (ArbitraryBS salt) (ArbitraryBS info) =
  let outLen = 32
  in case HKDF.hkdf algo secret salt info outLen of
       Left _ -> property $ counterexample "hkdf failed" False
       Right full -> case HKDF.hkdfExtract algo secret salt of
         Left _ -> property $ counterexample "hkdfExtract failed" False
         Right prk -> case HKDF.hkdfExpand algo prk info outLen of
           Left _ -> property $ counterexample "hkdfExpand failed" False
           Right expanded -> SB.secureBytesToByteString full === SB.secureBytesToByteString expanded

-- ---------------------------------------------------------------------------
-- Cipher Properties
-- ---------------------------------------------------------------------------

cipherProperties :: TestTree
cipherProperties = testGroup "Cipher"
  [ testProperty "encrypt then decrypt recovers plaintext" $
      prop_cipherRoundTrip
  , testProperty "different keys produce different ciphertexts" $
      prop_cipherDifferentKeys
  ]

prop_cipherRoundTrip :: CipherAlgorithm -> NonEmptyBS -> Property
prop_cipherRoundTrip algo (NonEmptyBS plaintext) = ioProperty $ do
  key <- Random.randomBytes (Cipher.cipherKeyLength algo)
  iv  <- if Cipher.cipherIVLength algo == 0
           then return BS.empty
           else Random.randomBytes (Cipher.cipherIVLength algo)
  encResult <- pure $ Cipher.encrypt algo key iv plaintext
  case encResult of
    Left err -> return $ counterexample ("encrypt failed: " ++ show err) False
    Right ct -> do
      decResult <- pure $ Cipher.decrypt algo key iv ct
      case decResult of
        Left err -> return $ counterexample ("decrypt failed: " ++ show err) False
        Right pt -> return $ pt === plaintext

prop_cipherDifferentKeys :: CipherAlgorithm -> Property
prop_cipherDifferentKeys algo =
  -- Use at least 16 bytes (one AES block) so collision probability is ~2^-128
  forAll (genBytes 16) $ \plaintext -> ioProperty $ do
    key1 <- Random.randomBytes (Cipher.cipherKeyLength algo)
    key2 <- Random.randomBytes (Cipher.cipherKeyLength algo)
    iv   <- if Cipher.cipherIVLength algo == 0
               then return BS.empty
               else Random.randomBytes (Cipher.cipherIVLength algo)
    if key1 == key2
      then return $ property True
      else do
        r1 <- pure $ Cipher.encrypt algo key1 iv plaintext
        r2 <- pure $ Cipher.encrypt algo key2 iv plaintext
        case (r1, r2) of
          (Right ct1, Right ct2) ->
            return $ counterexample "same ciphertext with different keys" (ct1 /= ct2)
          _ -> return $ property True

-- ---------------------------------------------------------------------------
-- Ed25519 Properties
-- ---------------------------------------------------------------------------

ed25519Properties :: TestTree
ed25519Properties = testGroup "Ed25519"
  [ testProperty "sign then verify succeeds" $
      prop_ed25519SignVerify
  , testProperty "verify fails with wrong message" $
      prop_ed25519WrongMessage
  , testProperty "signing is deterministic" $
      prop_ed25519DeterministicSign
  ]

prop_ed25519SignVerify :: ArbitraryBS -> Property
prop_ed25519SignVerify (ArbitraryBS msg) = ioProperty $ do
  (pub, priv) <- Ed25519.generateKeyPair
  case Ed25519.sign priv msg of
    Left err -> return $ counterexample ("sign failed: " ++ show err) False
    Right sig -> return $ Ed25519.verify pub msg sig === True

prop_ed25519WrongMessage :: ArbitraryBS -> ArbitraryBS -> Property
prop_ed25519WrongMessage (ArbitraryBS msg1) (ArbitraryBS msg2) =
  msg1 /= msg2 ==> ioProperty $ do
    (pub, priv) <- Ed25519.generateKeyPair
    case Ed25519.sign priv msg1 of
      Left err -> return $ counterexample ("sign failed: " ++ show err) False
      Right sig -> return $ Ed25519.verify pub msg2 sig === False

prop_ed25519DeterministicSign :: ArbitraryBS -> Property
prop_ed25519DeterministicSign (ArbitraryBS msg) = ioProperty $ do
  (_, priv) <- Ed25519.generateKeyPair
  let sig1 = Ed25519.sign priv msg
      sig2 = Ed25519.sign priv msg
  return $ sig1 === sig2

-- ---------------------------------------------------------------------------
-- X25519 Properties
-- ---------------------------------------------------------------------------

x25519Properties :: TestTree
x25519Properties = testGroup "X25519"
  [ testProperty "shared secret is symmetric" $
      prop_x25519SharedSecretSymmetric
  , testProperty "publicFromPrivate is deterministic" $
      prop_x25519PublicKeyDeterministic
  ]

prop_x25519SharedSecretSymmetric :: Property
prop_x25519SharedSecretSymmetric = ioProperty $ do
  (pubA, privA) <- X25519.generateKeyPair
  (pubB, privB) <- X25519.generateKeyPair
  let secretAB = fmap SB.secureBytesToByteString (X25519.computeSharedSecret privA pubB)
      secretBA = fmap SB.secureBytesToByteString (X25519.computeSharedSecret privB pubA)
  return $ secretAB === secretBA

prop_x25519PublicKeyDeterministic :: Property
prop_x25519PublicKeyDeterministic = ioProperty $ do
  (_, priv) <- X25519.generateKeyPair
  let pub1 = X25519.publicFromPrivate priv
      pub2 = X25519.publicFromPrivate priv
  return $ pub1 === pub2

-- ---------------------------------------------------------------------------
-- ECDSA Properties
-- ---------------------------------------------------------------------------

-- Keygen-heavy groups run 20 cases instead of the default 100 to keep CI
-- time reasonable.
ecdsaProperties :: TestTree
ecdsaProperties = localOption (QuickCheckTests 20) $ testGroup "ECDSA"
  [ testProperty "sign then verify succeeds (P256)" $
      (prop_ecdsaSignVerify P256)
  , testProperty "sign then verify succeeds (P384)" $
      (prop_ecdsaSignVerify P384)
  , testProperty "verify fails with wrong digest (P256)" $
      (prop_ecdsaWrongDigest P256)
  , testProperty "verify fails with wrong digest (P384)" $
      (prop_ecdsaWrongDigest P384)
  ]

prop_ecdsaSignVerify :: ECCurve -> Property
prop_ecdsaSignVerify curve = ioProperty $ do
  Right kp <- ECDSA.generateKeyPair curve
  Right pubKey <- ECDSA.ecPublicKeyOfPair kp
  msg <- Random.randomBytes 64
  let digest = Digest.hash SHA256 msg
  signResult <- ECDSA.ecdsaSign kp digest
  case signResult of
    Left err -> return $ counterexample ("sign failed: " ++ show err) False
    Right sig -> return $ ECDSA.ecdsaVerify pubKey digest sig === True

prop_ecdsaWrongDigest :: ECCurve -> Property
prop_ecdsaWrongDigest curve = ioProperty $ do
  Right kp <- ECDSA.generateKeyPair curve
  Right pubKey <- ECDSA.ecPublicKeyOfPair kp
  msg1 <- Random.randomBytes 64
  msg2 <- Random.randomBytes 64
  let digest1 = Digest.hash SHA256 msg1
      digest2 = Digest.hash SHA256 msg2
  if digest1 == digest2
    then return $ property True
    else do
      signResult <- ECDSA.ecdsaSign kp digest1
      case signResult of
        Left _ -> return $ property True
        Right sig -> return $ ECDSA.ecdsaVerify pubKey digest2 sig === False

-- ---------------------------------------------------------------------------
-- ECDH Properties
-- ---------------------------------------------------------------------------

ecdhProperties :: TestTree
ecdhProperties = localOption (QuickCheckTests 20) $ testGroup "ECDH"
  [ testProperty "shared secret is symmetric (P256)" $
      (prop_ecdhSymmetric P256)
  , testProperty "shared secret is symmetric (P384)" $
      (prop_ecdhSymmetric P384)
  ]

prop_ecdhSymmetric :: ECCurve -> Property
prop_ecdhSymmetric curve = ioProperty $ do
  Right kpA <- ECDH.generateECKeyPair curve
  Right kpB <- ECDH.generateECKeyPair curve
  Right pubA <- ECDH.ecPublicKeyOfPair kpA
  Right pubB <- ECDH.ecPublicKeyOfPair kpB
  secretAB <- pure $ ECDH.ecdhComputeSecret kpA pubB 32
  secretBA <- pure $ ECDH.ecdhComputeSecret kpB pubA 32
  case (secretAB, secretBA) of
    (Right sAB, Right sBA) -> return $ SB.secureBytesToByteString sAB === SB.secureBytesToByteString sBA
    (Left err, _) -> return $ counterexample ("A->B failed: " ++ show err) False
    (_, Left err) -> return $ counterexample ("B->A failed: " ++ show err) False

-- ---------------------------------------------------------------------------
-- RSA Properties (using pre-generated key pair)
-- ---------------------------------------------------------------------------

rsaProperties :: TestTree
rsaProperties = localOption (QuickCheckTests 20) $ testGroup "RSA"
  [ testProperty "PKCS#1 sign then verify round-trip" $
      prop_rsaPKCS1SignVerify
  , testProperty "PSS sign then verify round-trip" $
      prop_rsaPSSSignVerify
  , testProperty "OAEP encrypt then decrypt recovers plaintext" $
      prop_rsaOAEPRoundTrip
  , testProperty "key serialization round-trip" $
      prop_rsaKeySerializationRoundTrip
  ]

prop_rsaPKCS1SignVerify :: Property
prop_rsaPKCS1SignVerify = ioProperty $ do
  msg <- Random.randomBytes 64
  let digest = Digest.hash SHA256 msg
  signResult <- RSA.rsaSign rsaKeyPair SHA256 digest
  case signResult of
    Left err -> return $ counterexample ("sign failed: " ++ show err) False
    Right sig -> do
      verifyResult <- RSA.rsaVerify rsaPubKey SHA256 digest sig
      case verifyResult of
        Left err -> return $ counterexample ("verify failed: " ++ show err) False
        Right ok -> return $ ok === True

prop_rsaPSSSignVerify :: Property
prop_rsaPSSSignVerify = ioProperty $ do
  msg <- Random.randomBytes 64
  let digest = Digest.hash SHA256 msg
  signResult <- RSA.rsaSignPSS rsaKeyPair SHA256 digest
  case signResult of
    Left err -> return $ counterexample ("sign failed: " ++ show err) False
    Right sig -> do
      verifyResult <- RSA.rsaVerifyPSS rsaPubKey SHA256 digest sig
      case verifyResult of
        Left err -> return $ counterexample ("verify failed: " ++ show err) False
        Right ok -> return $ ok === True

prop_rsaOAEPRoundTrip :: Property
prop_rsaOAEPRoundTrip = forAll (choose (1, 190) >>= genBytes) $ \plaintext ->
  ioProperty $ do
    encResult <- RSA.rsaEncrypt rsaPubKey plaintext
    case encResult of
      Left err -> return $ counterexample ("encrypt failed: " ++ show err) False
      Right ct -> do
        decResult <- RSA.rsaDecrypt rsaKeyPair ct
        case decResult of
          Left err -> return $ counterexample ("decrypt failed: " ++ show err) False
          Right pt -> return $ pt === plaintext

prop_rsaKeySerializationRoundTrip :: Property
prop_rsaKeySerializationRoundTrip = ioProperty $ do
  -- Test public key round-trip
  Right pubBytes <- RSA.publicKeyToBytes rsaKeyPair
  Right _restoredPub <- RSA.publicKeyFromBytes pubBytes
  -- Test private key round-trip
  Right privBytes <- RSA.privateKeyToBytes rsaKeyPair
  Right restoredKP <- RSA.privateKeyFromBytes privBytes
  Right pubBytes2 <- RSA.publicKeyToBytes restoredKP
  -- The restored key should produce the same public key bytes
  return $ pubBytes === pubBytes2

-- ---------------------------------------------------------------------------
-- Base64 Properties
-- ---------------------------------------------------------------------------

base64Properties :: TestTree
base64Properties = testGroup "Base64"
  [ testProperty "encode then decode recovers original" $
      prop_base64RoundTrip
  , testProperty "encoded output is always valid (decodable)" $
      prop_base64EncodedLength
  ]

prop_base64RoundTrip :: ArbitraryBS -> Property
prop_base64RoundTrip (ArbitraryBS bs) =
  case Base64.encode bs of
    Left err -> counterexample ("encode failed: " ++ show err) False
    Right encoded -> case Base64.decode encoded of
      Left err -> counterexample ("decode failed: " ++ show err) False
      Right decoded -> decoded === bs

prop_base64EncodedLength :: ArbitraryBS -> Property
prop_base64EncodedLength (ArbitraryBS bs) =
  case Base64.encode bs of
    Left err -> counterexample ("encode failed: " ++ show err) False
    Right encoded -> case Base64.decode encoded of
      Left err -> counterexample ("decode of encoded data failed: " ++ show err) False
      Right _  -> property True

-- ---------------------------------------------------------------------------
-- Random Properties
-- ---------------------------------------------------------------------------

randomProperties :: TestTree
randomProperties = testGroup "Random"
  [ testProperty "randomBytes n produces exactly n bytes" $
      prop_randomLength
  , testProperty "two calls produce different output (n >= 16)" $
      prop_randomDistinct
  ]

prop_randomLength :: Positive Int -> Property
prop_randomLength (Positive n) =
  let n' = min n 1024  -- cap to avoid huge allocations
  in ioProperty $ do
       bs <- Random.randomBytes n'
       return $ BS.length bs === n'

prop_randomDistinct :: Property
prop_randomDistinct = ioProperty $ do
  bs1 <- Random.randomBytes 32
  bs2 <- Random.randomBytes 32
  return $ counterexample "two random outputs should differ" (bs1 /= bs2)

-- ---------------------------------------------------------------------------
-- Top-level test tree
-- ---------------------------------------------------------------------------

tests :: TestTree
tests = testGroup "Properties"
  [ digestProperties
  , aeadProperties
  , hmacProperties
  , hkdfProperties
  , cipherProperties
  , ed25519Properties
  , x25519Properties
  , ecdsaProperties
  , ecdhProperties
  , rsaProperties
  , base64Properties
  , randomProperties
  ]
