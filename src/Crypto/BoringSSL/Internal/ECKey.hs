module Crypto.BoringSSL.Internal.ECKey
  ( ECCurve(..)
  , ECKeyPair(..)
  , ECPublicKey(..)
  , generateECKeyPair
  , ecPublicKeyBytes
  , ecPrivateKeyBytes
  , ecKeyPairFromPrivateBytes
  , ecPublicKeyFromBytes
  , ecPublicKeyOfPair
  , curveNID
  , withECKeyPair
  , withECPublicKey
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Control.Exception (mask_, finally)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.ECKey

-- | Supported elliptic curves.
data ECCurve = P256 | P384 | P521
  deriving (Eq, Show)

-- | An EC key pair (private + public).
newtype ECKeyPair = ECKeyPair (ForeignPtr EC_KEY)

-- | An EC public key only.
newtype ECPublicKey = ECPublicKey (ForeignPtr EC_KEY)

-- | NID for a curve.
curveNID :: ECCurve -> CInt
curveNID P256 = 415   -- NID_X9_62_prime256v1 (from nid.h; consider hsc2hs)
curveNID P384 = 715   -- NID_secp384r1
curveNID P521 = 716   -- NID_secp521r1

-- | Use an ECKeyPair's raw pointer.
withECKeyPair :: ECKeyPair -> (Ptr EC_KEY -> IO a) -> IO a
withECKeyPair (ECKeyPair fptr) = withForeignPtr fptr

-- | Use an ECPublicKey's raw pointer.
withECPublicKey :: ECPublicKey -> (Ptr EC_KEY -> IO a) -> IO a
withECPublicKey (ECPublicKey fptr) = withForeignPtr fptr

------------------------------------------------------------------------
-- Internal helpers for chaining fallible IO steps
------------------------------------------------------------------------

-- | Chain fallible IO steps, short-circuiting on the first 'Left'.
(>>?) :: IO (Either CryptoError a) -> (a -> IO (Either CryptoError b)) -> IO (Either CryptoError b)
m >>? f = m >>= either (return . Left) f
infixl 1 >>?

-- | Return 'Left' if the pointer is null.
requireNonNull :: Ptr a -> CryptoError -> IO (Either CryptoError (Ptr a))
requireNonNull p err
  | p == nullPtr = return (Left err)
  | otherwise    = return (Right p)

-- | Return 'Left' if the C return code is not 1 (success).
requireSuccess :: CInt -> CryptoError -> IO (Either CryptoError ())
requireSuccess 1 _ = return (Right ())
requireSuccess _ err = return (Left err)

------------------------------------------------------------------------
-- Key generation
------------------------------------------------------------------------

-- | Generate a new EC key pair for the given curve.
generateECKeyPair :: ECCurve -> IO (Either CryptoError ECKeyPair)
generateECKeyPair curve = withBoundThread $ mask_ $ do
  clearBoringSSLError
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  requireNonNull keyPtr (AllocationFailure "generateECKeyPair: EC_KEY_new_by_curve_name failed")
    >>? \kp -> do
      rc <- c_EC_KEY_generate_key kp
      if rc /= 1
        then do
          c_EC_KEY_free kp
          merr <- getBoringSSLError
          return (Left (maybe (OperationFailed "generateECKeyPair: EC_KEY_generate_key failed") id merr))
        else do
          fptr <- newForeignPtr c_EC_KEY_free_funptr kp
          return (Right (ECKeyPair fptr))

------------------------------------------------------------------------
-- Key serialization
------------------------------------------------------------------------

-- | Get the uncompressed point encoding of the public key.
ecPublicKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPublicKeyBytes (ECKeyPair fptr) = withForeignPtr fptr $ \keyPtr -> do
  groupPtr <- c_EC_KEY_get0_group keyPtr
  requireNonNull groupPtr (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_group returned NULL")
    >>? \grp -> do
      pointPtr <- c_EC_KEY_get0_public_key keyPtr
      requireNonNull pointPtr (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_public_key returned NULL")
        >>? \pt -> do
          -- POINT_CONVERSION_UNCOMPRESSED = 4
          -- First query the size by passing NULL buffer
          len <- c_EC_POINT_point2oct grp pt 4 nullPtr 0 nullPtr
          if len == 0
            then return (Left (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct size query failed"))
            else do
              fptr <- BSI.mallocByteString (fromIntegral len)
              written <- withForeignPtr fptr $ \ptr ->
                c_EC_POINT_point2oct grp pt 4 (castPtr ptr) len nullPtr
              if written == 0
                then return (Left (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct failed"))
                else return (Right (BSI.BS fptr (fromIntegral written)))

-- | Get the private key as fixed-width big-endian bytes, zero-padded to the
-- full group order size. This avoids leaking information about the key value
-- through variable-length encoding and ensures compatibility with protocols
-- expecting fixed-width keys.
ecPrivateKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPrivateKeyBytes (ECKeyPair fptr) = withForeignPtr fptr $ \keyPtr -> do
  groupPtr <- c_EC_KEY_get0_group keyPtr
  requireNonNull groupPtr (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_group returned NULL")
    >>? \grp -> do
      degree <- c_EC_GROUP_get_degree grp
      let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
      bnPtr <- c_EC_KEY_get0_private_key keyPtr
      requireNonNull bnPtr (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_private_key returned NULL")
        >>? \bn -> do
          fptr <- BSI.mallocByteString numBytes
          rc <- withForeignPtr fptr $ \ptr ->
            c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) bn
          if rc /= 1
            then return (Left (OperationFailed "ecPrivateKeyBytes: BN_bn2bin_padded failed"))
            else return (Right (BSI.BS fptr numBytes))

------------------------------------------------------------------------
-- Key import
------------------------------------------------------------------------

-- | Reconstruct an EC key pair from a curve and private key bytes.
ecKeyPairFromPrivateBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECKeyPair)
ecKeyPairFromPrivateBytes curve privBytes = withBoundThread $ mask_ $ do
  clearBoringSSLError
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  requireNonNull keyPtr (AllocationFailure "ecKeyPairFromPrivateBytes: EC_KEY_new_by_curve_name failed")
    >>? \kp -> do
      -- Attach finalizer early: EC_KEY cleanup is now automatic on all paths.
      fptr <- newForeignPtr c_EC_KEY_free_funptr kp
      result <- withForeignPtr fptr $ \k ->
        setPrivateKey k >>? \() ->
        derivePublicKey k >>? \() -> do
        rc <- c_EC_KEY_check_key k
        requireSuccess rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_check_key failed")
      case result of
        Left err -> return (Left err)
        Right () -> return (Right (ECKeyPair fptr))
  where
    setPrivateKey kp =
      withByteString privBytes $ \privPtr privLen -> do
        bn <- c_BN_bin2bn privPtr privLen nullPtr
        requireNonNull bn (AllocationFailure "ecKeyPairFromPrivateBytes: BN_bin2bn failed")
          >>? \b -> do
            rc <- c_EC_KEY_set_private_key kp b
            c_BN_free b
            requireSuccess rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_private_key failed")

    derivePublicKey kp = do
      groupPtr <- c_EC_KEY_get0_group kp
      requireNonNull groupPtr (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_group returned NULL")
        >>? \grp -> do
          privBn <- c_EC_KEY_get0_private_key kp
          requireNonNull privBn (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_private_key returned NULL")
            >>? \bn -> do
              pubPoint <- c_EC_POINT_new grp
              requireNonNull pubPoint (AllocationFailure "ecKeyPairFromPrivateBytes: EC_POINT_new failed")
                >>? \pt ->
                  (do rc <- c_EC_POINT_mul grp pt bn nullPtr nullPtr nullPtr
                      requireSuccess rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_POINT_mul failed")
                        >>? \() -> do
                          rc2 <- c_EC_KEY_set_public_key kp pt
                          requireSuccess rc2 (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_public_key failed")
                  ) `finally` c_EC_POINT_free pt

-- | Parse an EC public key from uncompressed point bytes.
ecPublicKeyFromBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECPublicKey)
ecPublicKeyFromBytes curve pubBytes = withBoundThread $ mask_ $ do
  clearBoringSSLError
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  requireNonNull keyPtr (AllocationFailure "ecPublicKeyFromBytes: EC_KEY_new_by_curve_name failed")
    >>? \kp -> do
      -- Attach finalizer early: EC_KEY cleanup is now automatic on all paths.
      fptr <- newForeignPtr c_EC_KEY_free_funptr kp
      result <- withForeignPtr fptr $ \k -> do
        groupPtr <- c_EC_KEY_get0_group k
        requireNonNull groupPtr (OperationFailed "ecPublicKeyFromBytes: EC_KEY_get0_group returned NULL")
          >>? \grp -> do
            pubPoint <- c_EC_POINT_new grp
            requireNonNull pubPoint (AllocationFailure "ecPublicKeyFromBytes: EC_POINT_new failed")
              >>? \pt ->
                (withByteString pubBytes $ \bufPtr bufLen -> do
                  rc <- c_EC_POINT_oct2point grp pt bufPtr bufLen nullPtr
                  requireSuccess rc (DecodeError "ecPublicKeyFromBytes: EC_POINT_oct2point failed")
                    >>? \() -> do
                      rc2 <- c_EC_KEY_set_public_key k pt
                      requireSuccess rc2 (OperationFailed "ecPublicKeyFromBytes: EC_KEY_set_public_key failed")
                        >>? \() -> do
                          rc3 <- c_EC_KEY_check_key k
                          requireSuccess rc3 (DecodeError "ecPublicKeyFromBytes: EC_KEY_check_key failed (point not on curve)")
                ) `finally` c_EC_POINT_free pt
      case result of
        Left err -> return (Left err)
        Right () -> return (Right (ECPublicKey fptr))

------------------------------------------------------------------------
-- Key extraction
------------------------------------------------------------------------

-- | Extract the public key from a key pair.
ecPublicKeyOfPair :: ECKeyPair -> IO (Either CryptoError ECPublicKey)
ecPublicKeyOfPair kp = do
  result <- ecPublicKeyBytes kp
  case result of
    Left err -> return (Left err)
    Right pubBytes ->
      -- Determine curve from uncompressed point size
      case BS.length pubBytes of
        65  -> ecPublicKeyFromBytes P256 pubBytes  -- 1 + 2*32
        97  -> ecPublicKeyFromBytes P384 pubBytes  -- 1 + 2*48
        133 -> ecPublicKeyFromBytes P521 pubBytes  -- 1 + 2*66
        n   -> return (Left (OperationFailed ("ecPublicKeyOfPair: unexpected public key size " ++ show n)))
