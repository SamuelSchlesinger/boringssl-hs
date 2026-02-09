-- | Hybrid Public Key Encryption (RFC 9180).
--
-- HPKE enables a sender to encrypt messages to a receiver given
-- only their public key. Supports X25519, P-256, and ML-KEM KEMs.
module Crypto.BoringSSL.HPKE
  ( -- * Algorithm selection
    HPKEKEM(..)
  , HPKEKDF(..)
  , HPKEAEAD(..)
    -- * Key types
  , HPKEKey
    -- * Context types
  , SenderCtx
  , RecipientCtx
    -- * Key management
  , generateKey
  , keyFromPrivate
  , publicKeyBytes
  , privateKeyBytes
    -- * Sender setup
  , setupSender
    -- * Recipient setup
  , setupRecipient
    -- * Seal and open
  , senderSeal
  , recipientOpen
    -- * Export secret
  , senderExport
  , recipientExport
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.FFI.HPKE

-- | HPKE KEM algorithms.
data HPKEKEM = X25519HkdfSha256 | P256HkdfSha256 | MLKEM768 | MLKEM1024
  deriving (Eq, Show)

-- | HPKE KDF algorithms.
data HPKEKDF = HkdfSha256
  deriving (Eq, Show)

-- | HPKE AEAD algorithms.
data HPKEAEAD = Aes128Gcm | Aes256Gcm | ChaChaPoly
  deriving (Eq, Show)

-- | An HPKE key pair.
newtype HPKEKey = HPKEKey (ForeignPtr EVP_HPKE_KEY)

-- | A sender HPKE context (stateful, ordered seal operations).
newtype SenderCtx = SenderCtx (ForeignPtr EVP_HPKE_CTX)

-- | A recipient HPKE context (stateful, ordered open operations).
newtype RecipientCtx = RecipientCtx (ForeignPtr EVP_HPKE_CTX)

kemPtr :: HPKEKEM -> Ptr EVP_HPKE_KEM
kemPtr X25519HkdfSha256 = c_EVP_hpke_x25519_hkdf_sha256
kemPtr P256HkdfSha256   = c_EVP_hpke_p256_hkdf_sha256
kemPtr MLKEM768         = c_EVP_hpke_mlkem768
kemPtr MLKEM1024        = c_EVP_hpke_mlkem1024

kdfPtr :: HPKEKDF -> Ptr EVP_HPKE_KDF
kdfPtr HkdfSha256 = c_EVP_hpke_hkdf_sha256

aeadPtr :: HPKEAEAD -> Ptr EVP_HPKE_AEAD
aeadPtr Aes128Gcm  = c_EVP_hpke_aes_128_gcm
aeadPtr Aes256Gcm  = c_EVP_hpke_aes_256_gcm
aeadPtr ChaChaPoly = c_EVP_hpke_chacha20_poly1305

-- | Generate a new HPKE key pair for the given KEM.
generateKey :: HPKEKEM -> IO HPKEKey
generateKey kem = mask_ $ do
  key <- c_EVP_HPKE_KEY_new
  if key == nullPtr
    then fail "generateKey: EVP_HPKE_KEY_new failed"
    else do
      rc <- c_EVP_HPKE_KEY_generate key (kemPtr kem)
      if rc /= 1
        then do
          c_EVP_HPKE_KEY_free key
          fail "generateKey: EVP_HPKE_KEY_generate failed"
        else do
          fptr <- newForeignPtr c_EVP_HPKE_KEY_free_funptr key
          return (HPKEKey fptr)

-- | Initialize an HPKE key from a private key byte string.
keyFromPrivate :: HPKEKEM -> ByteString -> IO HPKEKey
keyFromPrivate kem privBytes = mask_ $ do
  key <- c_EVP_HPKE_KEY_new
  if key == nullPtr
    then fail "keyFromPrivate: EVP_HPKE_KEY_new failed"
    else do
      rc <- withByteString privBytes $ \privPtr privLen ->
        c_EVP_HPKE_KEY_init key (kemPtr kem) privPtr privLen
      if rc /= 1
        then do
          c_EVP_HPKE_KEY_free key
          fail "keyFromPrivate: EVP_HPKE_KEY_init failed"
        else do
          fptr <- newForeignPtr c_EVP_HPKE_KEY_free_funptr key
          return (HPKEKey fptr)

-- | Extract the public key bytes from an HPKE key pair.
publicKeyBytes :: HPKEKey -> IO ByteString
publicKeyBytes (HPKEKey fptr) =
  withForeignPtr fptr $ \key -> do
    let maxLen = evpHPKEMaxPublicKeyLength
    outFPtr <- BSI.mallocByteString maxLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_HPKE_KEY_public_key key (castPtr outPtr) outLenPtr (fromIntegral maxLen)
      if rc /= 1
        then fail "publicKeyBytes: EVP_HPKE_KEY_public_key failed"
        else do
          actualLen <- peek outLenPtr
          return (BSI.BS outFPtr (fromIntegral actualLen))

-- | Extract the private key bytes from an HPKE key pair.
privateKeyBytes :: HPKEKey -> IO ByteString
privateKeyBytes (HPKEKey fptr) =
  withForeignPtr fptr $ \key -> do
    let maxLen = evpHPKEMaxPrivateKeyLength
    outFPtr <- BSI.mallocByteString maxLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_HPKE_KEY_private_key key (castPtr outPtr) outLenPtr (fromIntegral maxLen)
      if rc /= 1
        then fail "privateKeyBytes: EVP_HPKE_KEY_private_key failed"
        else do
          actualLen <- peek outLenPtr
          return (BSI.BS outFPtr (fromIntegral actualLen))

-- | Set up a sender context. Returns @(enc, SenderCtx)@ where @enc@ is
-- the encapsulated key to send to the recipient.
setupSender :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
            -> IO (ByteString, SenderCtx)
setupSender kem kdf aead peerPubKey info = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then fail "setupSender: EVP_HPKE_CTX_new failed"
    else do
      let maxEncLen = evpHPKEMaxEncLength
      encFPtr <- BSI.mallocByteString maxEncLen
      result <- alloca $ \encLenPtr ->
        withForeignPtr encFPtr $ \encPtr ->
          withByteString peerPubKey $ \pkPtr pkLen ->
            withByteString info $ \infoPtr infoLen -> do
              rc <- c_EVP_HPKE_CTX_setup_sender ctx (castPtr encPtr) encLenPtr
                      (fromIntegral maxEncLen) (kemPtr kem) (kdfPtr kdf)
                      (aeadPtr aead) pkPtr pkLen infoPtr infoLen
              if rc /= 1
                then return Nothing
                else do
                  actualEncLen <- peek encLenPtr
                  return (Just (fromIntegral actualEncLen))
      case result of
        Nothing -> do
          c_EVP_HPKE_CTX_free ctx
          fail "setupSender: EVP_HPKE_CTX_setup_sender failed"
        Just encLen -> do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          return (BSI.BS encFPtr encLen, SenderCtx ctxFPtr)

-- | Set up a recipient context from an encapsulated key.
setupRecipient :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
               -> IO RecipientCtx
setupRecipient (HPKEKey keyFPtr) kdf aead enc info = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then fail "setupRecipient: EVP_HPKE_CTX_new failed"
    else do
      rc <- withForeignPtr keyFPtr $ \key ->
        withByteString enc $ \encPtr encLen ->
          withByteString info $ \infoPtr infoLen ->
            c_EVP_HPKE_CTX_setup_recipient ctx key (kdfPtr kdf) (aeadPtr aead)
              encPtr encLen infoPtr infoLen
      if rc /= 1
        then do
          c_EVP_HPKE_CTX_free ctx
          fail "setupRecipient: EVP_HPKE_CTX_setup_recipient failed"
        else do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          return (RecipientCtx ctxFPtr)

-- | Encrypt and authenticate plaintext using the sender context.
-- This is stateful: each call advances the internal sequence number.
senderSeal :: SenderCtx -> ByteString -> ByteString -> IO ByteString
senderSeal (SenderCtx fptr) plaintext ad =
  withForeignPtr fptr $ \ctx -> do
    overhead <- fromIntegral <$> c_EVP_HPKE_CTX_max_overhead ctx
    let maxOutLen = BS.length plaintext + overhead
    outFPtr <- BSI.mallocByteString maxOutLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        withByteString plaintext $ \inPtr inLen ->
          withByteString ad $ \adPtr adLen ->
            c_EVP_HPKE_CTX_seal ctx (castPtr outPtr) outLenPtr
              (fromIntegral maxOutLen) inPtr inLen adPtr adLen
      if rc /= 1
        then fail "senderSeal: EVP_HPKE_CTX_seal failed"
        else do
          actualLen <- peek outLenPtr
          return (BSI.BS outFPtr (fromIntegral actualLen))

-- | Decrypt and verify ciphertext using the recipient context.
-- This is stateful: each call advances the internal sequence number.
-- Returns 'Nothing' if decryption or authentication fails.
recipientOpen :: RecipientCtx -> ByteString -> ByteString -> IO (Maybe ByteString)
recipientOpen (RecipientCtx fptr) ciphertext ad =
  withForeignPtr fptr $ \ctx -> do
    let maxOutLen = BS.length ciphertext
    outFPtr <- BSI.mallocByteString maxOutLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        withByteString ciphertext $ \inPtr inLen ->
          withByteString ad $ \adPtr adLen ->
            c_EVP_HPKE_CTX_open ctx (castPtr outPtr) outLenPtr
              (fromIntegral maxOutLen) inPtr inLen adPtr adLen
      if rc /= 1
        then return Nothing
        else do
          actualLen <- peek outLenPtr
          return (Just (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Export a secret from the sender context.
senderExport :: SenderCtx -> ByteString -> Int -> IO ByteString
senderExport (SenderCtx fptr) context len =
  withForeignPtr fptr $ \ctx ->
    createByteString len $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen -> do
        rc <- c_EVP_HPKE_CTX_export ctx outPtr (fromIntegral len) ctxPtr ctxLen
        if rc /= 1
          then fail "senderExport: EVP_HPKE_CTX_export failed"
          else return ()

-- | Export a secret from the recipient context.
recipientExport :: RecipientCtx -> ByteString -> Int -> IO ByteString
recipientExport (RecipientCtx fptr) context len =
  withForeignPtr fptr $ \ctx ->
    createByteString len $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen -> do
        rc <- c_EVP_HPKE_CTX_export ctx outPtr (fromIntegral len) ctxPtr ctxLen
        if rc /= 1
          then fail "recipientExport: EVP_HPKE_CTX_export failed"
          else return ()
