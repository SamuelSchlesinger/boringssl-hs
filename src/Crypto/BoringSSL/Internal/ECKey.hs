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
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Control.Exception (mask_)

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

-- | Generate a new EC key pair for the given curve.
generateECKeyPair :: ECCurve -> IO (Either CryptoError ECKeyPair)
generateECKeyPair curve = mask_ $ do
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  if keyPtr == nullPtr
    then return (Left (AllocationFailure "generateECKeyPair: EC_KEY_new_by_curve_name failed"))
    else do
      rc <- c_EC_KEY_generate_key keyPtr
      if rc /= 1
        then do
          c_EC_KEY_free keyPtr
          merr <- getBoringSSLError
          return (Left (maybe (OperationFailed "generateECKeyPair: EC_KEY_generate_key failed") id merr))
        else do
          fptr <- newForeignPtr c_EC_KEY_free_funptr keyPtr
          return (Right (ECKeyPair fptr))

-- | Get the uncompressed point encoding of the public key.
ecPublicKeyBytes :: ECKeyPair -> IO ByteString
ecPublicKeyBytes (ECKeyPair fptr) = withForeignPtr fptr $ \keyPtr -> do
  groupPtr <- c_EC_KEY_get0_group keyPtr
  pointPtr <- c_EC_KEY_get0_public_key keyPtr
  -- POINT_CONVERSION_UNCOMPRESSED = 4
  -- First query the size by passing NULL buffer
  len <- c_EC_POINT_point2oct groupPtr pointPtr 4 nullPtr 0 nullPtr
  createByteString (fromIntegral len) $ \outPtr -> do
    _ <- c_EC_POINT_point2oct groupPtr pointPtr 4 outPtr len nullPtr
    return ()

-- | Get the private key as fixed-width big-endian bytes, zero-padded to the
-- full group order size. This avoids leaking information about the key value
-- through variable-length encoding and ensures compatibility with protocols
-- expecting fixed-width keys.
ecPrivateKeyBytes :: ECKeyPair -> IO ByteString
ecPrivateKeyBytes (ECKeyPair fptr) = withForeignPtr fptr $ \keyPtr -> do
  groupPtr <- c_EC_KEY_get0_group keyPtr
  degree <- c_EC_GROUP_get_degree groupPtr
  let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
  bnPtr <- c_EC_KEY_get0_private_key keyPtr
  createByteString numBytes $ \outPtr -> do
    _ <- c_BN_bn2bin_padded outPtr (fromIntegral numBytes) bnPtr
    return ()

-- | Reconstruct an EC key pair from a curve and private key bytes.
ecKeyPairFromPrivateBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECKeyPair)
ecKeyPairFromPrivateBytes curve privBytes = mask_ $ do
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  if keyPtr == nullPtr
    then return (Left (AllocationFailure "ecKeyPairFromPrivateBytes: EC_KEY_new_by_curve_name failed"))
    else do
      -- Set private key from bytes
      withByteString privBytes $ \privPtr privLen -> do
        bn <- c_BN_bin2bn privPtr privLen nullPtr
        if bn == nullPtr
          then do
            c_EC_KEY_free keyPtr
            return (Left (AllocationFailure "ecKeyPairFromPrivateBytes: BN_bin2bn failed"))
          else do
            rc <- c_EC_KEY_set_private_key keyPtr bn
            c_BN_free bn
            if rc /= 1
              then do
                c_EC_KEY_free keyPtr
                return (Left (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_private_key failed"))
              else do
                -- Derive public key: pubPoint = privKey * G
                groupPtr <- c_EC_KEY_get0_group keyPtr
                privBn <- c_EC_KEY_get0_private_key keyPtr
                pubPoint <- c_EC_POINT_new groupPtr
                rc2 <- c_EC_POINT_mul groupPtr pubPoint privBn nullPtr nullPtr nullPtr
                if rc2 /= 1
                  then do
                    c_EC_POINT_free pubPoint
                    c_EC_KEY_free keyPtr
                    return (Left (OperationFailed "ecKeyPairFromPrivateBytes: EC_POINT_mul failed"))
                  else do
                    rc3 <- c_EC_KEY_set_public_key keyPtr pubPoint
                    c_EC_POINT_free pubPoint
                    if rc3 /= 1
                      then do
                        c_EC_KEY_free keyPtr
                        return (Left (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_public_key failed"))
                      else do
                        rc4 <- c_EC_KEY_check_key keyPtr
                        if rc4 /= 1
                          then do
                            c_EC_KEY_free keyPtr
                            return (Left (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_check_key failed"))
                          else do
                            fptr <- newForeignPtr c_EC_KEY_free_funptr keyPtr
                            return (Right (ECKeyPair fptr))

-- | Parse an EC public key from uncompressed point bytes.
ecPublicKeyFromBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECPublicKey)
ecPublicKeyFromBytes curve pubBytes = mask_ $ do
  keyPtr <- c_EC_KEY_new_by_curve_name (curveNID curve)
  if keyPtr == nullPtr
    then return (Left (AllocationFailure "ecPublicKeyFromBytes: EC_KEY_new_by_curve_name failed"))
    else do
      groupPtr <- c_EC_KEY_get0_group keyPtr
      pubPoint <- c_EC_POINT_new groupPtr
      withByteString pubBytes $ \bufPtr bufLen -> do
        rc <- c_EC_POINT_oct2point groupPtr pubPoint bufPtr bufLen nullPtr
        if rc /= 1
          then do
            c_EC_POINT_free pubPoint
            c_EC_KEY_free keyPtr
            return (Left (DecodeError "ecPublicKeyFromBytes: EC_POINT_oct2point failed"))
          else do
            rc2 <- c_EC_KEY_set_public_key keyPtr pubPoint
            c_EC_POINT_free pubPoint
            if rc2 /= 1
              then do
                c_EC_KEY_free keyPtr
                return (Left (OperationFailed "ecPublicKeyFromBytes: EC_KEY_set_public_key failed"))
              else do
                rc3 <- c_EC_KEY_check_key keyPtr
                if rc3 /= 1
                  then do
                    c_EC_KEY_free keyPtr
                    return (Left (DecodeError "ecPublicKeyFromBytes: EC_KEY_check_key failed (point not on curve)"))
                  else do
                    fptr <- newForeignPtr c_EC_KEY_free_funptr keyPtr
                    return (Right (ECPublicKey fptr))

-- | Extract the public key from a key pair.
ecPublicKeyOfPair :: ECKeyPair -> IO (Either CryptoError ECPublicKey)
ecPublicKeyOfPair kp = do
  pubBytes <- ecPublicKeyBytes kp
  -- Determine curve from uncompressed point size
  case BS.length pubBytes of
    65  -> ecPublicKeyFromBytes P256 pubBytes  -- 1 + 2*32
    97  -> ecPublicKeyFromBytes P384 pubBytes  -- 1 + 2*48
    133 -> ecPublicKeyFromBytes P521 pubBytes  -- 1 + 2*66
    n   -> return (Left (OperationFailed ("ecPublicKeyOfPair: unexpected public key size " ++ show n)))
