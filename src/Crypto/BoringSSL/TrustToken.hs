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
  , issuerSetMetadataKey
  , issue
  , redeem
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Data.Word (Word8, Word32)
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_, finally)

import Crypto.BoringSSL.Internal.Buffer
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

-- | Generate a Trust Token key pair. Returns @(privateKey, publicKey)@.
generateKey :: TrustTokenMethod -> Word32 -> IO (ByteString, ByteString)
generateKey method keyId = do
  let maxPriv = trustTokenMaxPrivateKeySize
      maxPub  = trustTokenMaxPublicKeySize
  privFPtr <- BSI.mallocByteString maxPriv
  pubFPtr  <- BSI.mallocByteString maxPub
  alloca $ \privLenPtr ->
    alloca $ \pubLenPtr -> do
      rc <- withForeignPtr privFPtr $ \privPtr ->
        withForeignPtr pubFPtr $ \pubPtr ->
          c_TRUST_TOKEN_generate_key (methodPtr method)
            (castPtr privPtr) privLenPtr (fromIntegral maxPriv)
            (castPtr pubPtr) pubLenPtr (fromIntegral maxPub)
            keyId
      if rc /= 1
        then fail "generateKey: TRUST_TOKEN_generate_key failed"
        else do
          privLen <- peek privLenPtr
          pubLen  <- peek pubLenPtr
          return (BSI.BS privFPtr (fromIntegral privLen),
                  BSI.BS pubFPtr (fromIntegral pubLen))

-- | Create a new Trust Token client.
newClient :: TrustTokenMethod -> Int -> IO TrustTokenClient
newClient method maxBatchSize = mask_ $ do
  ctx <- c_TRUST_TOKEN_CLIENT_new (methodPtr method) (fromIntegral maxBatchSize)
  if ctx == nullPtr
    then fail "newClient: TRUST_TOKEN_CLIENT_new failed"
    else do
      fptr <- newForeignPtr c_TRUST_TOKEN_CLIENT_free_funptr ctx
      return (TrustTokenClient fptr)

-- | Add a public key to the client. Returns the key index.
clientAddKey :: TrustTokenClient -> ByteString -> IO Int
clientAddKey (TrustTokenClient fptr) key =
  withForeignPtr fptr $ \ctx ->
    alloca $ \idxPtr ->
      withByteString key $ \keyPtr keyLen -> do
        rc <- c_TRUST_TOKEN_CLIENT_add_key ctx idxPtr keyPtr keyLen
        if rc /= 1
          then fail "clientAddKey: TRUST_TOKEN_CLIENT_add_key failed"
          else fromIntegral <$> (peek idxPtr :: IO CSize)

-- | Begin token issuance. Returns the issuance request to send to the issuer.
beginIssuance :: TrustTokenClient -> Int -> IO ByteString
beginIssuance (TrustTokenClient fptr) count =
  withForeignPtr fptr $ \ctx ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr -> do
        rc <- c_TRUST_TOKEN_CLIENT_begin_issuance ctx outPtrPtr outLenPtr
                (fromIntegral count)
        if rc /= 1
          then fail "beginIssuance: TRUST_TOKEN_CLIENT_begin_issuance failed"
          else packOpenSSLBuffer outPtrPtr outLenPtr

-- | Finish token issuance by processing the issuer's response.
-- Returns @Just (tokens, keyIndex)@ on success.
finishIssuance :: TrustTokenClient -> ByteString -> IO (Maybe ([ByteString], Int))
finishIssuance (TrustTokenClient fptr) response =
  withForeignPtr fptr $ \ctx ->
    alloca $ \keyIdxPtr ->
      withByteString response $ \respPtr respLen -> do
        stack <- c_TRUST_TOKEN_CLIENT_finish_issuance ctx keyIdxPtr respPtr respLen
        if stack == nullPtr
          then return Nothing
          else do
            result <- extractTokens stack
              `finally` c_boringssl_sk_TRUST_TOKEN_pop_free stack
            keyIdx <- peek keyIdxPtr
            return (Just (result, fromIntegral (keyIdx :: CSize)))

-- | Extract token data from a STACK_OF(TRUST_TOKEN).
extractTokens :: Ptr STACK_TRUST_TOKEN -> IO [ByteString]
extractTokens stack = do
  n <- c_boringssl_sk_TRUST_TOKEN_num stack
  mapM (extractToken stack) [0 .. n - 1]

extractToken :: Ptr STACK_TRUST_TOKEN -> CSize -> IO ByteString
extractToken stack i = do
  tok <- c_boringssl_sk_TRUST_TOKEN_value stack i
  -- TRUST_TOKEN struct has data and len fields.
  -- We read data (ptr) at offset 0 and len at offset 8 (on 64-bit).
  dataPtr <- peek (castPtr tok :: Ptr (Ptr CUChar))
  len <- peek (castPtr tok `plusPtr` sizeOfPtr :: Ptr CSize)
  BS.packCStringLen (castPtr dataPtr, fromIntegral len)
  where
    sizeOfPtr = 8  -- sizeof(void*) on 64-bit platforms

-- | Begin token redemption. Returns the redemption request.
beginRedemption :: TrustTokenClient -> ByteString -> ByteString -> IO ByteString
beginRedemption (TrustTokenClient fptr) tokenData clientData =
  withForeignPtr fptr $ \ctx ->
    withByteString tokenData $ \tokDataPtr tokDataLen -> do
      tok <- c_TRUST_TOKEN_new tokDataPtr tokDataLen
      if tok == nullPtr
        then fail "beginRedemption: TRUST_TOKEN_new failed"
        else do
          result <- alloca $ \outPtrPtr ->
            alloca $ \outLenPtr ->
              withByteString clientData $ \cdPtr cdLen -> do
                rc <- c_TRUST_TOKEN_CLIENT_begin_redemption ctx outPtrPtr outLenPtr
                        tok cdPtr cdLen 0
                if rc /= 1
                  then do
                    c_TRUST_TOKEN_free tok
                    fail "beginRedemption: TRUST_TOKEN_CLIENT_begin_redemption failed"
                  else do
                    c_TRUST_TOKEN_free tok
                    packOpenSSLBuffer outPtrPtr outLenPtr
          return result

-- | Finish redemption by processing the issuer's response.
-- Returns @Just (rr, sig)@ on success.
finishRedemption :: TrustTokenClient -> ByteString -> IO (Maybe (ByteString, ByteString))
finishRedemption (TrustTokenClient fptr) response =
  withForeignPtr fptr $ \ctx ->
    alloca $ \rrPtrPtr ->
      alloca $ \rrLenPtr ->
        alloca $ \sigPtrPtr ->
          alloca $ \sigLenPtr ->
            withByteString response $ \respPtr respLen -> do
              rc <- c_TRUST_TOKEN_CLIENT_finish_redemption ctx rrPtrPtr rrLenPtr
                      sigPtrPtr sigLenPtr respPtr respLen
              if rc /= 1
                then return Nothing
                else do
                  rr <- packOpenSSLBuffer rrPtrPtr rrLenPtr
                  sig <- packOpenSSLBuffer sigPtrPtr sigLenPtr
                  return (Just (rr, sig))

-- | Create a new Trust Token issuer.
newIssuer :: TrustTokenMethod -> Int -> IO TrustTokenIssuer
newIssuer method maxBatchSize = mask_ $ do
  ctx <- c_TRUST_TOKEN_ISSUER_new (methodPtr method) (fromIntegral maxBatchSize)
  if ctx == nullPtr
    then fail "newIssuer: TRUST_TOKEN_ISSUER_new failed"
    else do
      fptr <- newForeignPtr c_TRUST_TOKEN_ISSUER_free_funptr ctx
      return (TrustTokenIssuer fptr)

-- | Add a private key to the issuer.
issuerAddKey :: TrustTokenIssuer -> ByteString -> IO ()
issuerAddKey (TrustTokenIssuer fptr) key =
  withForeignPtr fptr $ \ctx ->
    withByteString key $ \keyPtr keyLen -> do
      rc <- c_TRUST_TOKEN_ISSUER_add_key ctx keyPtr keyLen
      if rc /= 1
        then fail "issuerAddKey: TRUST_TOKEN_ISSUER_add_key failed"
        else return ()

-- | Set the metadata key for the issuer.
issuerSetMetadataKey :: TrustTokenIssuer -> ByteString -> IO ()
issuerSetMetadataKey (TrustTokenIssuer fptr) key =
  withForeignPtr fptr $ \ctx ->
    withByteString key $ \keyPtr keyLen -> do
      rc <- c_TRUST_TOKEN_ISSUER_set_metadata_key ctx keyPtr keyLen
      if rc /= 1
        then fail "issuerSetMetadataKey: TRUST_TOKEN_ISSUER_set_metadata_key failed"
        else return ()

-- | Issue tokens in response to a client request.
-- Returns @Just (response, tokensIssued)@ on success.
issue :: TrustTokenIssuer -> ByteString -> Word32 -> Word8 -> Int
      -> IO (Maybe (ByteString, Int))
issue (TrustTokenIssuer fptr) request publicMeta privateMeta maxIssuance =
  withForeignPtr fptr $ \ctx ->
    alloca $ \outPtrPtr ->
      alloca $ \outLenPtr ->
        alloca $ \tokensIssuedPtr ->
          withByteString request $ \reqPtr reqLen -> do
            rc <- c_TRUST_TOKEN_ISSUER_issue ctx outPtrPtr outLenPtr
                    tokensIssuedPtr reqPtr reqLen publicMeta privateMeta
                    (fromIntegral maxIssuance)
            if rc /= 1
              then return Nothing
              else do
                resp <- packOpenSSLBuffer outPtrPtr outLenPtr
                issued <- peek tokensIssuedPtr
                return (Just (resp, fromIntegral (issued :: CSize)))

-- | Redeem a token. Returns @Just (publicMetadata, privateMetadata,
-- tokenData, clientData)@ on success.
redeem :: TrustTokenIssuer -> ByteString
       -> IO (Maybe (Word32, Word8, ByteString, ByteString))
redeem (TrustTokenIssuer fptr) request =
  withForeignPtr fptr $ \ctx ->
    alloca $ \pubPtr ->
      alloca $ \privPtr ->
        alloca $ \tokenPtrPtr ->
          alloca $ \cdPtrPtr ->
            alloca $ \cdLenPtr ->
              withByteString request $ \reqPtr reqLen -> do
                rc <- c_TRUST_TOKEN_ISSUER_redeem ctx pubPtr privPtr
                        tokenPtrPtr cdPtrPtr cdLenPtr reqPtr reqLen
                if rc /= 1
                  then return Nothing
                  else do
                    pubMeta <- peek pubPtr
                    privMeta <- peek privPtr
                    tokenRawPtr <- peek tokenPtrPtr
                    -- Extract token data
                    tokDataPtr <- peek (castPtr tokenRawPtr :: Ptr (Ptr CUChar))
                    tokLen <- peek (castPtr tokenRawPtr `plusPtr` 8 :: Ptr CSize)
                    tokenBs <- BS.packCStringLen (castPtr tokDataPtr, fromIntegral tokLen)
                    c_TRUST_TOKEN_free tokenRawPtr
                    clientData <- packOpenSSLBuffer cdPtrPtr cdLenPtr
                    return (Just (pubMeta, privMeta, tokenBs, clientData))
