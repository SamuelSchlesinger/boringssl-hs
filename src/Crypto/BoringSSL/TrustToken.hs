-- | Trust Token issuance and redemption.
--
-- Implements Privacy Pass-style anonymous tokens with limited
-- private metadata. Supports PMBToken and VOPRF protocol variants.
module Crypto.BoringSSL.TrustToken
  ( -- * Method selection
    TrustTokenMethod(..)
    -- * Key generation
  , generateKey
    -- * Client
  , TrustTokenClient
  , newClient
  , clientAddKey
  , beginIssuance
  , finishIssuance
  , beginRedemption
  , finishRedemption
    -- * Issuer
  , TrustTokenIssuer
  , newIssuer
  , issuerAddKey
  , issue
  , redeem
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Data.Word (Word8, Word32)
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.TrustToken

-- | Trust Token protocol method.
data TrustTokenMethod
  = ExperimentV2VOPRF
  | ExperimentV2PMB
  | PstV1VOPRF
  | PstV1PMB
  deriving (Eq, Show)

-- | A Trust Token client context.
newtype TrustTokenClient = TrustTokenClient (ForeignPtr TRUST_TOKEN_CLIENT)

-- | A Trust Token issuer context.
newtype TrustTokenIssuer = TrustTokenIssuer (ForeignPtr TRUST_TOKEN_ISSUER)

methodPtr :: TrustTokenMethod -> Ptr TRUST_TOKEN_METHOD
methodPtr ExperimentV2VOPRF = c_TRUST_TOKEN_experiment_v2_voprf
methodPtr ExperimentV2PMB   = c_TRUST_TOKEN_experiment_v2_pmb
methodPtr PstV1VOPRF        = c_TRUST_TOKEN_pst_v1_voprf
methodPtr PstV1PMB          = c_TRUST_TOKEN_pst_v1_pmb

-- | Generate a Trust Token key pair. Returns @Right (privateKey, publicKey)@.
generateKey :: TrustTokenMethod -> Word32 -> IO (Either CryptoError (ByteString, ByteString))
generateKey method keyId = do
  let maxPriv = trustTokenMaxPrivateKeySize
      maxPub  = trustTokenMaxPublicKeySize
  privFPtr <- BSI.mallocByteString maxPriv
  pubFPtr  <- BSI.mallocByteString maxPub
  runExceptT $ allocaE $ \privLenPtr -> allocaE $ \pubLenPtr -> do
    rc <- liftIO $ withForeignPtr privFPtr $ \privPtr ->
      withForeignPtr pubFPtr $ \pubPtr ->
        c_TRUST_TOKEN_generate_key (methodPtr method)
          (castPtr privPtr) privLenPtr (fromIntegral maxPriv)
          (castPtr pubPtr) pubLenPtr (fromIntegral maxPub)
          keyId
    checkRC (OperationFailed "generateKey: TRUST_TOKEN_generate_key failed") rc
    privLen <- liftIO $ peek privLenPtr
    pubLen  <- liftIO $ peek pubLenPtr
    return (BSI.BS privFPtr (fromIntegral privLen),
            BSI.BS pubFPtr (fromIntegral pubLen))

-- | Create a new Trust Token client.
newClient :: TrustTokenMethod -> Int -> IO (Either CryptoError TrustTokenClient)
newClient method maxBatchSize = runExceptT $ maskE_ $ do
  ctx <- liftIO (c_TRUST_TOKEN_CLIENT_new (methodPtr method) (fromIntegral maxBatchSize))
    >>= nonNull (AllocationFailure "newClient: TRUST_TOKEN_CLIENT_new failed")
  fptr <- liftIO $ newForeignPtr c_TRUST_TOKEN_CLIENT_free_funptr ctx
  return (TrustTokenClient fptr)

-- | Add a public key to the client. Returns the key index.
clientAddKey :: TrustTokenClient -> ByteString -> IO (Either CryptoError Int)
clientAddKey (TrustTokenClient fptr) key =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \idxPtr -> do
      rc <- liftIO $ withByteString key $ \keyPtr keyLen ->
        c_TRUST_TOKEN_CLIENT_add_key ctx idxPtr keyPtr keyLen
      checkRC (OperationFailed "clientAddKey: TRUST_TOKEN_CLIENT_add_key failed") rc
      idx <- liftIO $ peek idxPtr
      return (fromIntegral (idx :: CSize))

-- | Begin token issuance. Returns the issuance request to send to the issuer.
beginIssuance :: TrustTokenClient -> Int -> IO (Either CryptoError ByteString)
beginIssuance (TrustTokenClient fptr) count =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
      rc <- liftIO $ c_TRUST_TOKEN_CLIENT_begin_issuance ctx outPtrPtr outLenPtr
              (fromIntegral count)
      checkRC (OperationFailed "beginIssuance: TRUST_TOKEN_CLIENT_begin_issuance failed") rc
      liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr

-- | Finish token issuance by processing the issuer's response.
-- Returns @Right (tokens, keyIndex)@ on success.
finishIssuance :: TrustTokenClient -> ByteString -> IO (Either CryptoError ([ByteString], Int))
finishIssuance (TrustTokenClient fptr) response =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \keyIdxPtr -> do
      stack <- liftIO (withByteString response $ \respPtr respLen ->
        c_TRUST_TOKEN_CLIENT_finish_issuance ctx keyIdxPtr respPtr respLen)
        >>= nonNull (OperationFailed "finishIssuance: TRUST_TOKEN_CLIENT_finish_issuance failed")
      result <- finallyE (liftIO $ extractTokens stack)
                         (c_boringssl_sk_TRUST_TOKEN_pop_free stack)
      keyIdx <- liftIO $ peek keyIdxPtr
      return (result, fromIntegral (keyIdx :: CSize))

-- | Extract token data from a STACK_OF(TRUST_TOKEN).
extractTokens :: Ptr STACK_TRUST_TOKEN -> IO [ByteString]
extractTokens stack = do
  n <- c_boringssl_sk_TRUST_TOKEN_num stack
  mapM (extractToken stack) [0 .. n - 1]

extractToken :: Ptr STACK_TRUST_TOKEN -> CSize -> IO ByteString
extractToken stack i = do
  tok <- c_boringssl_sk_TRUST_TOKEN_value stack i
  if tok == nullPtr
    then return BS.empty
    else do
      dataPtr <- c_boringssl_TRUST_TOKEN_data tok
      len <- c_boringssl_TRUST_TOKEN_len tok
      BS.packCStringLen (castPtr dataPtr, fromIntegral len)

-- | Begin token redemption. Returns the redemption request.
beginRedemption :: TrustTokenClient -> ByteString -> ByteString -> IO (Either CryptoError ByteString)
beginRedemption (TrustTokenClient fptr) tokenData clientData =
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    tok <- liftIO (withByteString tokenData $ \tokDataPtr tokDataLen ->
      c_TRUST_TOKEN_new tokDataPtr tokDataLen)
      >>= nonNull (AllocationFailure "beginRedemption: TRUST_TOKEN_new failed")
    finallyE
      (allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> do
        rc <- liftIO $ withByteString clientData $ \cdPtr cdLen ->
          c_TRUST_TOKEN_CLIENT_begin_redemption ctx outPtrPtr outLenPtr
            tok cdPtr cdLen 0
        checkRC (OperationFailed "beginRedemption: TRUST_TOKEN_CLIENT_begin_redemption failed") rc
        liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr)
      (c_TRUST_TOKEN_free tok)

-- | Finish redemption by processing the issuer's response.
-- Returns @Right (rr, sig)@ on success.
finishRedemption :: TrustTokenClient -> ByteString -> IO (Either CryptoError (ByteString, ByteString))
finishRedemption (TrustTokenClient fptr) response =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \rrPtrPtr -> allocaE $ \rrLenPtr ->
      allocaE $ \sigPtrPtr -> allocaE $ \sigLenPtr -> do
        rc <- liftIO $ withByteString response $ \respPtr respLen ->
          c_TRUST_TOKEN_CLIENT_finish_redemption ctx rrPtrPtr rrLenPtr
            sigPtrPtr sigLenPtr respPtr respLen
        checkRC (OperationFailed "finishRedemption: TRUST_TOKEN_CLIENT_finish_redemption failed") rc
        rr <- liftIO $ packOpenSSLBuffer rrPtrPtr rrLenPtr
        sig <- liftIO $ packOpenSSLBuffer sigPtrPtr sigLenPtr
        return (rr, sig)

-- | Create a new Trust Token issuer.
newIssuer :: TrustTokenMethod -> Int -> IO (Either CryptoError TrustTokenIssuer)
newIssuer method maxBatchSize = runExceptT $ maskE_ $ do
  ctx <- liftIO (c_TRUST_TOKEN_ISSUER_new (methodPtr method) (fromIntegral maxBatchSize))
    >>= nonNull (AllocationFailure "newIssuer: TRUST_TOKEN_ISSUER_new failed")
  fptr <- liftIO $ newForeignPtr c_TRUST_TOKEN_ISSUER_free_funptr ctx
  return (TrustTokenIssuer fptr)

-- | Add a private key to the issuer.
issuerAddKey :: TrustTokenIssuer -> ByteString -> IO (Either CryptoError ())
issuerAddKey (TrustTokenIssuer fptr) key =
  withForeignPtr fptr $ \ctx -> runExceptT $ do
    rc <- liftIO $ withByteString key $ \keyPtr keyLen ->
      c_TRUST_TOKEN_ISSUER_add_key ctx keyPtr keyLen
    checkRC (OperationFailed "issuerAddKey: TRUST_TOKEN_ISSUER_add_key failed") rc

-- | Issue tokens in response to a client request.
-- Returns @Right (response, tokensIssued)@ on success.
issue :: TrustTokenIssuer -> ByteString -> Word32 -> Word8 -> Int
      -> IO (Either CryptoError (ByteString, Int))
issue (TrustTokenIssuer fptr) request publicMeta privateMeta maxIssuance =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \outPtrPtr -> allocaE $ \outLenPtr -> allocaE $ \tokensIssuedPtr -> do
      rc <- liftIO $ withByteString request $ \reqPtr reqLen ->
        c_TRUST_TOKEN_ISSUER_issue ctx outPtrPtr outLenPtr
          tokensIssuedPtr reqPtr reqLen publicMeta privateMeta
          (fromIntegral maxIssuance)
      checkRC (OperationFailed "issue: TRUST_TOKEN_ISSUER_issue failed") rc
      resp <- liftIO $ packOpenSSLBuffer outPtrPtr outLenPtr
      issued <- liftIO $ peek tokensIssuedPtr
      return (resp, fromIntegral (issued :: CSize))

-- | Redeem a token. Returns @Right (publicMetadata, privateMetadata,
-- tokenData, clientData)@ on success.
redeem :: TrustTokenIssuer -> ByteString
       -> IO (Either CryptoError (Word32, Word8, ByteString, ByteString))
redeem (TrustTokenIssuer fptr) request =
  withForeignPtr fptr $ \ctx -> runExceptT $
    allocaE $ \pubPtr -> allocaE $ \privPtr ->
      allocaE $ \tokenPtrPtr -> allocaE $ \cdPtrPtr -> allocaE $ \cdLenPtr -> do
        rc <- liftIO $ withByteString request $ \reqPtr reqLen ->
          c_TRUST_TOKEN_ISSUER_redeem ctx pubPtr privPtr
            tokenPtrPtr cdPtrPtr cdLenPtr reqPtr reqLen
        checkRC (OperationFailed "redeem: TRUST_TOKEN_ISSUER_redeem failed") rc
        pubMeta <- liftIO $ peek pubPtr
        privMeta <- liftIO $ peek privPtr
        tokenRawPtr <- liftIO $ peek tokenPtrPtr
        tokDataPtr <- liftIO $ c_boringssl_TRUST_TOKEN_data tokenRawPtr
        tokLen <- liftIO $ c_boringssl_TRUST_TOKEN_len tokenRawPtr
        tokenBs <- liftIO $ BS.packCStringLen (castPtr tokDataPtr, fromIntegral tokLen)
        liftIO $ c_TRUST_TOKEN_free tokenRawPtr
        clientData <- liftIO $ packOpenSSLBuffer cdPtrPtr cdLenPtr
        return (pubMeta, privMeta, tokenBs, clientData)
