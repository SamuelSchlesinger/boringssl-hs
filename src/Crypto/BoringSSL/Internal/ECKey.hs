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
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import Control.Exception (mask_)

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.ExceptT
import Crypto.BoringSSL.Internal.FFI.Constants
import Crypto.BoringSSL.Internal.FFI.ECKey

-- | Supported elliptic curves.
data ECCurve = P256 | P384 | P521
  deriving (Eq, Show)

-- | An EC key pair (private + public), storing the curve alongside the key.
data ECKeyPair = ECKeyPair !ECCurve !(ForeignPtr EC_KEY)

-- | An EC public key only.
newtype ECPublicKey = ECPublicKey (ForeignPtr EC_KEY)

-- | NID for a curve, derived from BoringSSL headers at compile time.
curveNID :: ECCurve -> CInt
curveNID P256 = nidX962Prime256v1
curveNID P384 = nidSecp384r1
curveNID P521 = nidSecp521r1

-- | Use an ECKeyPair's raw pointer.
withECKeyPair :: ECKeyPair -> (Ptr EC_KEY -> IO a) -> IO a
withECKeyPair (ECKeyPair _curve fptr) = withForeignPtr fptr

-- | Use an ECPublicKey's raw pointer.
withECPublicKey :: ECPublicKey -> (Ptr EC_KEY -> IO a) -> IO a
withECPublicKey (ECPublicKey fptr) = withForeignPtr fptr

------------------------------------------------------------------------
-- Key generation
------------------------------------------------------------------------

-- | Generate a new EC key pair for the given curve.
generateECKeyPair :: ECCurve -> IO (Either CryptoError ECKeyPair)
generateECKeyPair curve = withBoundThread $ mask_ $ runExceptT $ do
  liftIO clearBoringSSLError
  kp <- liftIO (c_EC_KEY_new_by_curve_name (curveNID curve))
    >>= \p -> nonNull p (AllocationFailure "generateECKeyPair: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  rc <- liftIO $ withForeignPtr fptr $ \k -> c_EC_KEY_generate_key k
  checkRCError rc "generateECKeyPair: EC_KEY_generate_key failed"
  return (ECKeyPair curve fptr)

------------------------------------------------------------------------
-- Key serialization
------------------------------------------------------------------------

-- | Get the uncompressed point encoding of the public key.
ecPublicKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPublicKeyBytes (ECKeyPair _curve fptr) = withForeignPtr fptr $ \keyPtr -> runExceptT $ do
  grp <- liftIO (c_EC_KEY_get0_group keyPtr)
    >>= \p -> nonNull p (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_group returned NULL")
  pt <- liftIO (c_EC_KEY_get0_public_key keyPtr)
    >>= \p -> nonNull p (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_public_key returned NULL")
  -- POINT_CONVERSION_UNCOMPRESSED = 4
  -- First query the size by passing NULL buffer
  len <- liftIO $ c_EC_POINT_point2oct grp pt 4 nullPtr 0 nullPtr
  checkRC (if len == 0 then 0 else 1)
    (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct size query failed")
  bsFptr <- liftIO $ BSI.mallocByteString (fromIntegral len)
  written <- liftIO $ withForeignPtr bsFptr $ \ptr ->
    c_EC_POINT_point2oct grp pt 4 (castPtr ptr) len nullPtr
  checkRC (if written == 0 then 0 else 1)
    (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct failed")
  return (BSI.BS bsFptr (fromIntegral written))

-- | Get the private key as fixed-width big-endian bytes, zero-padded to the
-- full group order size. This avoids leaking information about the key value
-- through variable-length encoding and ensures compatibility with protocols
-- expecting fixed-width keys.
ecPrivateKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPrivateKeyBytes (ECKeyPair _curve fptr) = withForeignPtr fptr $ \keyPtr -> runExceptT $ do
  grp <- liftIO (c_EC_KEY_get0_group keyPtr)
    >>= \p -> nonNull p (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_group returned NULL")
  degree <- liftIO $ c_EC_GROUP_get_degree grp
  let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
  bn <- liftIO (c_EC_KEY_get0_private_key keyPtr)
    >>= \p -> nonNull p (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_private_key returned NULL")
  bsFptr <- liftIO $ BSI.mallocByteString numBytes
  rc <- liftIO $ withForeignPtr bsFptr $ \ptr ->
    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) bn
  checkRC rc (OperationFailed "ecPrivateKeyBytes: BN_bn2bin_padded failed")
  return (BSI.BS bsFptr numBytes)

------------------------------------------------------------------------
-- Key import
------------------------------------------------------------------------

-- | Reconstruct an EC key pair from a curve and private key bytes.
ecKeyPairFromPrivateBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECKeyPair)
ecKeyPairFromPrivateBytes curve privBytes = withBoundThread $ mask_ $ runExceptT $ do
  liftIO clearBoringSSLError
  kp <- liftIO (c_EC_KEY_new_by_curve_name (curveNID curve))
    >>= \p -> nonNull p (AllocationFailure "ecKeyPairFromPrivateBytes: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  ExceptT $ withForeignPtr fptr $ \k -> runExceptT $ do
    setPrivateKey k
    derivePublicKey k
    rc <- liftIO $ c_EC_KEY_check_key k
    checkRC rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_check_key failed")
  return (ECKeyPair curve fptr)
  where
    setPrivateKey kp = ExceptT $
      withByteString privBytes $ \privPtr privLen -> runExceptT $ do
        b <- liftIO (c_BN_bin2bn privPtr privLen nullPtr)
          >>= \p -> nonNull p (AllocationFailure "ecKeyPairFromPrivateBytes: BN_bin2bn failed")
        rc <- liftIO $ c_EC_KEY_set_private_key kp b
        liftIO $ c_BN_free b
        checkRC rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_private_key failed")

    derivePublicKey kp = do
      grp <- liftIO (c_EC_KEY_get0_group kp)
        >>= \p -> nonNull p (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_group returned NULL")
      bn <- liftIO (c_EC_KEY_get0_private_key kp)
        >>= \p -> nonNull p (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_private_key returned NULL")
      pt <- liftIO (c_EC_POINT_new grp)
        >>= \p -> nonNull p (AllocationFailure "ecKeyPairFromPrivateBytes: EC_POINT_new failed")
      flip finallyE (c_EC_POINT_free pt) $ do
        rc <- liftIO $ c_EC_POINT_mul grp pt bn nullPtr nullPtr nullPtr
        checkRC rc (OperationFailed "ecKeyPairFromPrivateBytes: EC_POINT_mul failed")
        rc2 <- liftIO $ c_EC_KEY_set_public_key kp pt
        checkRC rc2 (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_public_key failed")

-- | Parse an EC public key from uncompressed point bytes.
ecPublicKeyFromBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECPublicKey)
ecPublicKeyFromBytes curve pubBytes = withBoundThread $ mask_ $ runExceptT $ do
  liftIO clearBoringSSLError
  kp <- liftIO (c_EC_KEY_new_by_curve_name (curveNID curve))
    >>= \p -> nonNull p (AllocationFailure "ecPublicKeyFromBytes: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  ExceptT $ withForeignPtr fptr $ \k -> runExceptT $ do
    grp <- liftIO (c_EC_KEY_get0_group k)
      >>= \p -> nonNull p (OperationFailed "ecPublicKeyFromBytes: EC_KEY_get0_group returned NULL")
    pt <- liftIO (c_EC_POINT_new grp)
      >>= \p -> nonNull p (AllocationFailure "ecPublicKeyFromBytes: EC_POINT_new failed")
    flip finallyE (c_EC_POINT_free pt) $ ExceptT $
      withByteString pubBytes $ \bufPtr bufLen -> runExceptT $ do
        rc <- liftIO $ c_EC_POINT_oct2point grp pt bufPtr bufLen nullPtr
        checkRC rc (DecodeError "ecPublicKeyFromBytes: EC_POINT_oct2point failed")
        rc2 <- liftIO $ c_EC_KEY_set_public_key k pt
        checkRC rc2 (OperationFailed "ecPublicKeyFromBytes: EC_KEY_set_public_key failed")
        rc3 <- liftIO $ c_EC_KEY_check_key k
        checkRC rc3 (DecodeError "ecPublicKeyFromBytes: EC_KEY_check_key failed (point not on curve)")
  return (ECPublicKey fptr)

------------------------------------------------------------------------
-- Key extraction
------------------------------------------------------------------------

-- | Extract the public key from a key pair.
ecPublicKeyOfPair :: ECKeyPair -> IO (Either CryptoError ECPublicKey)
ecPublicKeyOfPair kp@(ECKeyPair curve _fptr) = runExceptT $ do
  pubBytes <- ExceptT $ ecPublicKeyBytes kp
  ExceptT $ ecPublicKeyFromBytes curve pubBytes
