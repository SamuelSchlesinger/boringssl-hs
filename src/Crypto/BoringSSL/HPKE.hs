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
    -- * Error type
  , BoringSSLError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import Control.Concurrent.MVar

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.HPKE

-- | HPKE KEM algorithms.
data HPKEKEM
  = X25519HkdfSha256
  | P256HkdfSha256
  | XWing
    -- ^ X-Wing hybrid KEM combining X25519 and ML-KEM-768.
  | MLKEM768
  | MLKEM1024
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
-- Thread-safe: concurrent calls are serialized via an internal lock.
data SenderCtx = SenderCtx !(MVar ()) !(ForeignPtr EVP_HPKE_CTX)

-- | A recipient HPKE context (stateful, ordered open operations).
-- Thread-safe: concurrent calls are serialized via an internal lock.
data RecipientCtx = RecipientCtx !(MVar ()) !(ForeignPtr EVP_HPKE_CTX)

kemPtr :: HPKEKEM -> Ptr EVP_HPKE_KEM
kemPtr X25519HkdfSha256 = c_EVP_hpke_x25519_hkdf_sha256
kemPtr P256HkdfSha256   = c_EVP_hpke_p256_hkdf_sha256
kemPtr XWing            = c_EVP_hpke_xwing
kemPtr MLKEM768         = c_EVP_hpke_mlkem768
kemPtr MLKEM1024        = c_EVP_hpke_mlkem1024

kdfPtr :: HPKEKDF -> Ptr EVP_HPKE_KDF
kdfPtr HkdfSha256 = c_EVP_hpke_hkdf_sha256

aeadPtr :: HPKEAEAD -> Ptr EVP_HPKE_AEAD
aeadPtr Aes128Gcm  = c_EVP_hpke_aes_128_gcm
aeadPtr Aes256Gcm  = c_EVP_hpke_aes_256_gcm
aeadPtr ChaChaPoly = c_EVP_hpke_chacha20_poly1305

-- | Generate a new HPKE key pair for the given KEM.
generateKey :: HPKEKEM -> IO (Either BoringSSLError HPKEKey)
generateKey kem = mask_ $ do
  key <- c_EVP_HPKE_KEY_new
  if key == nullPtr
    then return (Left (BoringSSLError 0 "generateKey: EVP_HPKE_KEY_new failed"))
    else do
      rc <- c_EVP_HPKE_KEY_generate key (kemPtr kem)
      if rc /= 1
        then do
          c_EVP_HPKE_KEY_free key
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "generateKey: EVP_HPKE_KEY_generate failed") id merr))
        else do
          fptr <- newForeignPtr c_EVP_HPKE_KEY_free_funptr key
          return (Right (HPKEKey fptr))

-- | Initialize an HPKE key from a private key byte string.
keyFromPrivate :: HPKEKEM -> ByteString -> IO (Either BoringSSLError HPKEKey)
keyFromPrivate kem privBytes = mask_ $ do
  key <- c_EVP_HPKE_KEY_new
  if key == nullPtr
    then return (Left (BoringSSLError 0 "keyFromPrivate: EVP_HPKE_KEY_new failed"))
    else do
      rc <- withByteString privBytes $ \privPtr privLen ->
        c_EVP_HPKE_KEY_init key (kemPtr kem) privPtr privLen
      if rc /= 1
        then do
          c_EVP_HPKE_KEY_free key
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "keyFromPrivate: EVP_HPKE_KEY_init failed") id merr))
        else do
          fptr <- newForeignPtr c_EVP_HPKE_KEY_free_funptr key
          return (Right (HPKEKey fptr))

-- | Extract the public key bytes from an HPKE key pair.
publicKeyBytes :: HPKEKey -> IO (Either BoringSSLError ByteString)
publicKeyBytes (HPKEKey fptr) =
  withForeignPtr fptr $ \key -> do
    let maxLen = evpHPKEMaxPublicKeyLength
    outFPtr <- BSI.mallocByteString maxLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_HPKE_KEY_public_key key (castPtr outPtr) outLenPtr (fromIntegral maxLen)
      if rc /= 1
        then do
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "publicKeyBytes: EVP_HPKE_KEY_public_key failed") id merr))
        else do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Extract the private key bytes from an HPKE key pair.
privateKeyBytes :: HPKEKey -> IO (Either BoringSSLError ByteString)
privateKeyBytes (HPKEKey fptr) =
  withForeignPtr fptr $ \key -> do
    let maxLen = evpHPKEMaxPrivateKeyLength
    outFPtr <- BSI.mallocByteString maxLen
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        c_EVP_HPKE_KEY_private_key key (castPtr outPtr) outLenPtr (fromIntegral maxLen)
      if rc /= 1
        then do
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "privateKeyBytes: EVP_HPKE_KEY_private_key failed") id merr))
        else do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Set up a sender context. Returns @(enc, SenderCtx)@ where @enc@ is
-- the encapsulated key to send to the recipient.
setupSender :: HPKEKEM -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
            -> IO (Either BoringSSLError (ByteString, SenderCtx))
setupSender kem kdf aead peerPubKey info = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then return (Left (BoringSSLError 0 "setupSender: EVP_HPKE_CTX_new failed"))
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
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "setupSender: EVP_HPKE_CTX_setup_sender failed") id merr))
        Just encLen -> do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          lock <- newMVar ()
          return (Right (BSI.BS encFPtr encLen, SenderCtx lock ctxFPtr))

-- | Set up a recipient context from an encapsulated key.
setupRecipient :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
               -> IO (Either BoringSSLError RecipientCtx)
setupRecipient (HPKEKey keyFPtr) kdf aead enc info = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then return (Left (BoringSSLError 0 "setupRecipient: EVP_HPKE_CTX_new failed"))
    else do
      rc <- withForeignPtr keyFPtr $ \key ->
        withByteString enc $ \encPtr encLen ->
          withByteString info $ \infoPtr infoLen ->
            c_EVP_HPKE_CTX_setup_recipient ctx key (kdfPtr kdf) (aeadPtr aead)
              encPtr encLen infoPtr infoLen
      if rc /= 1
        then do
          c_EVP_HPKE_CTX_free ctx
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "setupRecipient: EVP_HPKE_CTX_setup_recipient failed") id merr))
        else do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          lock <- newMVar ()
          return (Right (RecipientCtx lock ctxFPtr))

-- | Set up an authenticated sender context. Like 'setupSender', but the
-- sender authenticates themselves with their own 'HPKEKey'. The recipient
-- can verify the sender's identity via 'setupAuthRecipient'.
-- Returns @(enc, SenderCtx)@ where @enc@ is the encapsulated key.
setupAuthSender :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
                -> IO (Either BoringSSLError (ByteString, SenderCtx))
setupAuthSender (HPKEKey authKeyFPtr) kdf aead peerPubKey info = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then return (Left (BoringSSLError 0 "setupAuthSender: EVP_HPKE_CTX_new failed"))
    else do
      let maxEncLen = evpHPKEMaxEncLength
      encFPtr <- BSI.mallocByteString maxEncLen
      result <- alloca $ \encLenPtr ->
        withForeignPtr encFPtr $ \encPtr ->
          withForeignPtr authKeyFPtr $ \authKey ->
            withByteString peerPubKey $ \pkPtr pkLen ->
              withByteString info $ \infoPtr infoLen -> do
                rc <- c_EVP_HPKE_CTX_setup_auth_sender ctx (castPtr encPtr)
                        encLenPtr (fromIntegral maxEncLen) authKey (kdfPtr kdf)
                        (aeadPtr aead) pkPtr pkLen infoPtr infoLen
                if rc /= 1
                  then return Nothing
                  else do
                    actualEncLen <- peek encLenPtr
                    return (Just (fromIntegral actualEncLen))
      case result of
        Nothing -> do
          c_EVP_HPKE_CTX_free ctx
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "setupAuthSender: EVP_HPKE_CTX_setup_auth_sender failed") id merr))
        Just encLen -> do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          lock <- newMVar ()
          return (Right (BSI.BS encFPtr encLen, SenderCtx lock ctxFPtr))

-- | Set up an authenticated recipient context. Like 'setupRecipient', but
-- also verifies that the sender authenticated themselves with the given
-- public key. The sender must have used 'setupAuthSender'.
setupAuthRecipient :: HPKEKey -> HPKEKDF -> HPKEAEAD -> ByteString -> ByteString
                   -> ByteString -> IO (Either BoringSSLError RecipientCtx)
setupAuthRecipient (HPKEKey keyFPtr) kdf aead enc info senderPubKey = mask_ $ do
  ctx <- c_EVP_HPKE_CTX_new
  if ctx == nullPtr
    then return (Left (BoringSSLError 0 "setupAuthRecipient: EVP_HPKE_CTX_new failed"))
    else do
      rc <- withForeignPtr keyFPtr $ \key ->
        withByteString enc $ \encPtr encLen ->
          withByteString info $ \infoPtr infoLen ->
            withByteString senderPubKey $ \spkPtr spkLen ->
              c_EVP_HPKE_CTX_setup_auth_recipient ctx key (kdfPtr kdf)
                (aeadPtr aead) encPtr encLen infoPtr infoLen spkPtr spkLen
      if rc /= 1
        then do
          c_EVP_HPKE_CTX_free ctx
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "setupAuthRecipient: EVP_HPKE_CTX_setup_auth_recipient failed") id merr))
        else do
          ctxFPtr <- newForeignPtr c_EVP_HPKE_CTX_free_funptr ctx
          lock <- newMVar ()
          return (Right (RecipientCtx lock ctxFPtr))

-- | Encrypt and authenticate plaintext using the sender context.
-- This is stateful: each call advances the internal sequence number.
-- Thread-safe: concurrent calls are serialized.
senderSeal :: SenderCtx -> ByteString -> ByteString -> IO (Either BoringSSLError ByteString)
senderSeal (SenderCtx lock fptr) plaintext ad =
  withMVar lock $ \_ ->
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
        then do
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "senderSeal: EVP_HPKE_CTX_seal failed") id merr))
        else do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Decrypt and verify ciphertext using the recipient context.
-- This is stateful: each call advances the internal sequence number.
-- Thread-safe: concurrent calls are serialized.
recipientOpen :: RecipientCtx -> ByteString -> ByteString -> IO (Either BoringSSLError ByteString)
recipientOpen (RecipientCtx lock fptr) ciphertext ad =
  withMVar lock $ \_ ->
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
        then do
          merr <- getBoringSSLError
          return (Left (maybe (BoringSSLError 0 "recipientOpen: decryption or authentication failed") id merr))
        else do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Export a secret from the sender context.
-- Thread-safe: concurrent calls are serialized.
senderExport :: SenderCtx -> ByteString -> Int -> IO (Either BoringSSLError ByteString)
senderExport _ _ len
  | len <= 0 = return (Left (BoringSSLError 0 "senderExport: output length must be positive"))
senderExport (SenderCtx lock fptr) context len =
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> do
    outFPtr <- BSI.mallocByteString len
    rc <- withForeignPtr outFPtr $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen ->
        c_EVP_HPKE_CTX_export ctx (castPtr outPtr) (fromIntegral len) ctxPtr ctxLen
    if rc /= 1
      then do
        merr <- getBoringSSLError
        return (Left (maybe (BoringSSLError 0 "senderExport: EVP_HPKE_CTX_export failed") id merr))
      else return (Right (BSI.BS outFPtr len))

-- | Export a secret from the recipient context.
-- Thread-safe: concurrent calls are serialized.
recipientExport :: RecipientCtx -> ByteString -> Int -> IO (Either BoringSSLError ByteString)
recipientExport _ _ len
  | len <= 0 = return (Left (BoringSSLError 0 "recipientExport: output length must be positive"))
recipientExport (RecipientCtx lock fptr) context len =
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> do
    outFPtr <- BSI.mallocByteString len
    rc <- withForeignPtr outFPtr $ \outPtr ->
      withByteString context $ \ctxPtr ctxLen ->
        c_EVP_HPKE_CTX_export ctx (castPtr outPtr) (fromIntegral len) ctxPtr ctxLen
    if rc /= 1
      then do
        merr <- getBoringSSLError
        return (Left (maybe (BoringSSLError 0 "recipientExport: EVP_HPKE_CTX_export failed") id merr))
      else return (Right (BSI.BS outFPtr len))
