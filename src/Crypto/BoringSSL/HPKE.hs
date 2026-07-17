-- | Hybrid Public Key Encryption (RFC 9180).
--
-- HPKE enables a sender to encrypt messages to a receiver given
-- only their public key. Supports X25519, P-256, X-Wing, and ML-KEM KEMs.
-- Includes both base mode and authenticated sender mode (Auth).
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
    -- * Authenticated sender setup
  , setupAuthSender
    -- * Recipient setup
  , setupRecipient
    -- * Authenticated recipient setup
  , setupAuthRecipient
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
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import Control.Concurrent.MVar

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.HPKE

-- | HPKE KEM algorithms (RFC 9180 and post-quantum extensions).
data HPKEKEM
  = DHKEM_X25519_HKDF_SHA256
    -- ^ RFC 9180 DHKEM(X25519, HKDF-SHA256).
  | DHKEM_P256_HKDF_SHA256
    -- ^ RFC 9180 DHKEM(P-256, HKDF-SHA256).
  | XWing
    -- ^ X-Wing hybrid KEM combining X25519 and ML-KEM-768.
  | MLKEM768
  | MLKEM1024
  deriving (Eq, Show)

-- | HPKE KDF algorithms.
data HPKEKDF = HKDF_SHA256
  deriving (Eq, Show)

-- | HPKE AEAD algorithms.
data HPKEAEAD = AES128GCM | AES256GCM | ChaCha20Poly1305
  deriving (Eq, Show)

-- | An HPKE key pair.
newtype HPKEKey = HPKEKey (ForeignPtr EVP_HPKE_KEY)

-- | A sender HPKE context (stateful, ordered seal operations).
-- Thread-safe: concurrent calls are serialized via an internal lock.
data SenderCtx = SenderCtx !(MVar ()) !(ForeignPtr EVP_HPKE_CTX)

-- | A recipient HPKE context (stateful, ordered open operations).
-- Thread-safe: concurrent calls are serialized via an internal lock.
data RecipientCtx = RecipientCtx !(MVar ()) !(ForeignPtr EVP_HPKE_CTX)

kemPtr :: HPKEKEM -> Ptr EVP_HPKE_KEM
kemPtr DHKEM_X25519_HKDF_SHA256 = c_EVP_hpke_x25519_hkdf_sha256
kemPtr DHKEM_P256_HKDF_SHA256   = c_EVP_hpke_p256_hkdf_sha256
kemPtr XWing            = c_EVP_hpke_xwing
kemPtr MLKEM768         = c_EVP_hpke_mlkem768
kemPtr MLKEM1024        = c_EVP_hpke_mlkem1024

kdfPtr :: HPKEKDF -> Ptr EVP_HPKE_KDF
kdfPtr HKDF_SHA256 = c_EVP_hpke_hkdf_sha256

aeadPtr :: HPKEAEAD -> Ptr EVP_HPKE_AEAD
aeadPtr AES128GCM  = c_EVP_hpke_aes_128_gcm
aeadPtr AES256GCM  = c_EVP_hpke_aes_256_gcm
aeadPtr ChaCha20Poly1305 = c_EVP_hpke_chacha20_poly1305

-- | Generate a new HPKE key pair for the given KEM.
generateKey :: HPKEKEM -> IO (Either CryptoError HPKEKey)
generateKey kem = withBoundThread $ mask_ $ runExceptT $ do
  key <- liftIO c_EVP_HPKE_KEY_new
    >>= nonNull (AllocationFailure "generateKey: EVP_HPKE_KEY_new failed")
  liftIO clearBoringSSLError
  rc <- liftIO $ c_EVP_HPKE_KEY_generate key (kemPtr kem)
  if rc == 1
    then do
      fptr <- liftIO $ newForeignPtr c_EVP_HPKE_KEY_free_funptr key
      return (HPKEKey fptr)
    else do
      liftIO $ c_EVP_HPKE_KEY_free key
      throwBoringSSLError (OperationFailed "generateKey: EVP_HPKE_KEY_generate failed")

-- | Initialize an HPKE key from a private key byte string.
keyFromPrivate :: HPKEKEM -> ByteString -> IO (Either CryptoError HPKEKey)
keyFromPrivate kem privBytes = withBoundThread $ mask_ $ runExceptT $ do
  key <- liftIO c_EVP_HPKE_KEY_new
    >>= nonNull (AllocationFailure "keyFromPrivate: EVP_HPKE_KEY_new failed")
  liftIO clearBoringSSLError
  rc <- liftIO $ withByteString privBytes $ \privPtr privLen ->
    c_EVP_HPKE_KEY_init key (kemPtr kem) privPtr privLen
  if rc == 1
    then do
      fptr <- liftIO $ newForeignPtr c_EVP_HPKE_KEY_free_funptr key
      return (HPKEKey fptr)
    else do
      liftIO $ c_EVP_HPKE_KEY_free key
      throwBoringSSLError (OperationFailed "keyFromPrivate: EVP_HPKE_KEY_init failed")

-- | Extract the public key bytes from an HPKE key pair.
publicKeyBytes :: HPKEKey -> IO (Either CryptoError ByteString)
publicKeyBytes (HPKEKey fptr) = withBoundThread $
  withForeignPtr fptr $ \key -> runExceptT $
    withOutputBuffer evpHPKEMaxPublicKeyLength
      (\outPtr outLenPtr ->
        c_EVP_HPKE_KEY_public_key key (castPtr outPtr) outLenPtr
          (fromIntegral evpHPKEMaxPublicKeyLength))
      "publicKeyBytes: EVP_HPKE_KEY_public_key failed"

-- | Extract the private key bytes from an HPKE key pair.
privateKeyBytes :: HPKEKey -> IO (Either CryptoError ByteString)
privateKeyBytes (HPKEKey fptr) = withBoundThread $
  withForeignPtr fptr $ \key -> runExceptT $
    withOutputBuffer evpHPKEMaxPrivateKeyLength
      (\outPtr outLenPtr ->
        c_EVP_HPKE_KEY_private_key key (castPtr outPtr) outLenPtr
          (fromIntegral evpHPKEMaxPrivateKeyLength))
      "privateKeyBytes: EVP_HPKE_KEY_private_key failed"

-- | Set up a sender context. Returns @(enc, SenderCtx)@ where @enc@ is
-- the encapsulated key to send to the recipient.
setupSender :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
            -> IO (Either CryptoError (ByteString, SenderCtx))
setupSender kem kdf aead peerPubKey info = withBoundThread $ mask_ $ runExceptT $ do
  ctx <- liftIO c_EVP_HPKE_CTX_new
    >>= nonNull (AllocationFailure "setupSender: EVP_HPKE_CTX_new failed")
  let maxEncLen = evpHPKEMaxEncLength
  encFPtr <- liftIO $ BSI.mallocByteString maxEncLen
  allocaE $ \encLenPtr -> do
    liftIO clearBoringSSLError
    rc <- liftIO $ withForeignPtr encFPtr $ \encPtr ->
      withByteString peerPubKey $ \pkPtr pkLen ->
        withByteString info $ \infoPtr infoLen ->
          c_EVP_HPKE_CTX_setup_sender ctx (castPtr encPtr) encLenPtr
            (fromIntegral maxEncLen) (kemPtr kem) (kdfPtr kdf)
            (aeadPtr aead) pkPtr pkLen infoPtr infoLen
    if rc == 1
      then do
        actualEncLen <- liftIO $ peek encLenPtr
        ctxFPtr <- liftIO $ newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
        lock <- liftIO $ newMVar ()
        return (BSI.BS encFPtr (fromIntegral actualEncLen), SenderCtx lock ctxFPtr)
      else do
        liftIO $ c_EVP_HPKE_CTX_free ctx
        throwBoringSSLError (OperationFailed "setupSender: EVP_HPKE_CTX_setup_sender failed")

-- | Set up a recipient context from an encapsulated key.
setupRecipient :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
               -> IO (Either CryptoError RecipientCtx)
setupRecipient (HPKEKey keyFPtr) kdf aead enc info = withBoundThread $ mask_ $ runExceptT $ do
  ctx <- liftIO c_EVP_HPKE_CTX_new
    >>= nonNull (AllocationFailure "setupRecipient: EVP_HPKE_CTX_new failed")
  liftIO clearBoringSSLError
  rc <- liftIO $ withForeignPtr keyFPtr $ \key ->
    withByteString enc $ \encPtr encLen ->
      withByteString info $ \infoPtr infoLen ->
        c_EVP_HPKE_CTX_setup_recipient ctx key (kdfPtr kdf) (aeadPtr aead)
          encPtr encLen infoPtr infoLen
  if rc == 1
    then do
      ctxFPtr <- liftIO $ newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
      lock <- liftIO $ newMVar ()
      return (RecipientCtx lock ctxFPtr)
    else do
      liftIO $ c_EVP_HPKE_CTX_free ctx
      throwBoringSSLError (OperationFailed "setupRecipient: EVP_HPKE_CTX_setup_recipient failed")

-- | Set up an authenticated sender context. Like 'setupSender', but the
-- sender authenticates themselves with their own 'HPKEKey'. The recipient
-- can verify the sender's identity via 'setupAuthRecipient'.
-- Returns @(enc, SenderCtx)@ where @enc@ is the encapsulated key.
setupAuthSender :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
                -> IO (Either CryptoError (ByteString, SenderCtx))
setupAuthSender (HPKEKey authKeyFPtr) kdf aead peerPubKey info = withBoundThread $ mask_ $ runExceptT $ do
  ctx <- liftIO c_EVP_HPKE_CTX_new
    >>= nonNull (AllocationFailure "setupAuthSender: EVP_HPKE_CTX_new failed")
  let maxEncLen = evpHPKEMaxEncLength
  encFPtr <- liftIO $ BSI.mallocByteString maxEncLen
  allocaE $ \encLenPtr -> do
    liftIO clearBoringSSLError
    rc <- liftIO $ withForeignPtr encFPtr $ \encPtr ->
      withForeignPtr authKeyFPtr $ \authKey ->
        withByteString peerPubKey $ \pkPtr pkLen ->
          withByteString info $ \infoPtr infoLen ->
            c_EVP_HPKE_CTX_setup_auth_sender ctx (castPtr encPtr)
              encLenPtr (fromIntegral maxEncLen) authKey (kdfPtr kdf)
              (aeadPtr aead) pkPtr pkLen infoPtr infoLen
    if rc == 1
      then do
        actualEncLen <- liftIO $ peek encLenPtr
        ctxFPtr <- liftIO $ newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
        lock <- liftIO $ newMVar ()
        return (BSI.BS encFPtr (fromIntegral actualEncLen), SenderCtx lock ctxFPtr)
      else do
        liftIO $ c_EVP_HPKE_CTX_free ctx
        throwBoringSSLError (OperationFailed "setupAuthSender: EVP_HPKE_CTX_setup_auth_sender failed")

-- | Set up an authenticated recipient context. Like 'setupRecipient', but
-- also verifies that the sender authenticated themselves with the given
-- public key. The sender must have used 'setupAuthSender'.
setupAuthRecipient :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
                   -> ByteString -> IO (Either CryptoError RecipientCtx)
setupAuthRecipient (HPKEKey keyFPtr) kdf aead enc info senderPubKey = withBoundThread $ mask_ $ runExceptT $ do
  ctx <- liftIO c_EVP_HPKE_CTX_new
    >>= nonNull (AllocationFailure "setupAuthRecipient: EVP_HPKE_CTX_new failed")
  liftIO clearBoringSSLError
  rc <- liftIO $ withForeignPtr keyFPtr $ \key ->
    withByteString enc $ \encPtr encLen ->
      withByteString info $ \infoPtr infoLen ->
        withByteString senderPubKey $ \spkPtr spkLen ->
          c_EVP_HPKE_CTX_setup_auth_recipient ctx key (kdfPtr kdf)
            (aeadPtr aead) encPtr encLen infoPtr infoLen spkPtr spkLen
  if rc == 1
    then do
      ctxFPtr <- liftIO $ newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
      lock <- liftIO $ newMVar ()
      return (RecipientCtx lock ctxFPtr)
    else do
      liftIO $ c_EVP_HPKE_CTX_free ctx
      throwBoringSSLError (OperationFailed "setupAuthRecipient: EVP_HPKE_CTX_setup_auth_recipient failed")

-- | Encrypt and authenticate plaintext using the sender context.
-- This is stateful: each call advances the internal sequence number.
-- The recipient must call 'recipientOpen' in the same order that
-- 'senderSeal' was called, otherwise decryption will fail.
-- Thread-safe: concurrent calls are serialized.
senderSeal :: SenderCtx -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
senderSeal (SenderCtx lock fptr) plaintext ad = withBoundThread $
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    overhead <- liftIO $ fromIntegral <$> c_EVP_HPKE_CTX_max_overhead ctx
    let maxOutLen = BS.length plaintext + overhead
    withOutputBuffer maxOutLen
      (\outPtr outLenPtr ->
        withByteString plaintext $ \inPtr inLen ->
          withByteString ad $ \adPtr adLen ->
            c_EVP_HPKE_CTX_seal ctx (castPtr outPtr) outLenPtr
              (fromIntegral maxOutLen) inPtr inLen adPtr adLen)
      "senderSeal: EVP_HPKE_CTX_seal failed"

-- | Decrypt and verify ciphertext using the recipient context.
-- This is stateful: each call advances the internal sequence number, so
-- __messages must be opened in exactly the order 'senderSeal' produced
-- them__ — an out-of-order, tampered, or wrong-associated-data message
-- is reported as 'Left' 'AuthenticationFailed', and unauthenticated
-- plaintext is never returned.
-- Thread-safe: concurrent calls are serialized.
recipientOpen :: RecipientCtx -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
recipientOpen (RecipientCtx lock fptr) ciphertext ad = fmap remap $ withBoundThread $
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    let maxOutLen = BS.length ciphertext
    withOutputBuffer maxOutLen
      (\outPtr outLenPtr ->
        withByteString ciphertext $ \inPtr inLen ->
          withByteString ad $ \adPtr adLen ->
            c_EVP_HPKE_CTX_open ctx (castPtr outPtr) outLenPtr
              (fromIntegral maxOutLen) inPtr inLen adPtr adLen)
      "recipientOpen"
  where
    -- With the output buffer correctly sized by construction, the only
    -- failure EVP_HPKE_CTX_open can report is tag verification.
    remap (Left _) = Left AuthenticationFailed
    remap r        = r

-- | Export a secret from the sender context.
-- Thread-safe: concurrent calls are serialized.
senderExport :: SenderCtx -> ByteString -> Int -> IO (Either CryptoError ByteString)
senderExport _ _ len
  | len <= 0 = return (Left (InvalidInput "senderExport: output length must be positive"))
senderExport (SenderCtx lock fptr) context len = withBoundThread $
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    outFPtr <- liftIO $ BSI.mallocByteString len
    liftIO clearBoringSSLError
    rc <- liftIO $ withForeignPtr outFPtr $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen ->
        c_EVP_HPKE_CTX_export ctx (castPtr outPtr) (fromIntegral len) ctxPtr ctxLen
    checkRCError "senderExport: EVP_HPKE_CTX_export failed" rc
    return (BSI.BS outFPtr len)

-- | Export a secret from the recipient context.
-- Thread-safe: concurrent calls are serialized.
recipientExport :: RecipientCtx -> ByteString -> Int -> IO (Either CryptoError ByteString)
recipientExport _ _ len
  | len <= 0 = return (Left (InvalidInput "recipientExport: output length must be positive"))
recipientExport (RecipientCtx lock fptr) context len = withBoundThread $
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    outFPtr <- liftIO $ BSI.mallocByteString len
    liftIO clearBoringSSLError
    rc <- liftIO $ withForeignPtr outFPtr $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen ->
        c_EVP_HPKE_CTX_export ctx (castPtr outPtr) (fromIntegral len) ctxPtr ctxLen
    checkRCError "recipientExport: EVP_HPKE_CTX_export failed" rc
    return (BSI.BS outFPtr len)
