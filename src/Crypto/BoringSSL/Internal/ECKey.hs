module Crypto.BoringSSL.Internal.ECKey
  ( ECCurve(..)
  , ECKeyPair(..)
  , ECPublicKey(..)
  , generateECKeyPair
  , ecPublicKeyBytes
  , ecPrivateKeyBytes
  , ecPrivateKeySecureBytes
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
import Crypto.BoringSSL.Internal.SecureBytes (SecureBytes, createSecureBytes, withSecureBytes)
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
    >>= nonNull (AllocationFailure "generateECKeyPair: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  rc <- liftIO $ withForeignPtr fptr $ \k -> c_EC_KEY_generate_key k
  checkRCError "generateECKeyPair: EC_KEY_generate_key failed" rc
  return (ECKeyPair curve fptr)

------------------------------------------------------------------------
-- Key serialization
------------------------------------------------------------------------

-- | Get the uncompressed point encoding of the public key.
ecPublicKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPublicKeyBytes (ECKeyPair _curve fptr) = withForeignPtr fptr $ \keyPtr -> runExceptT $ do
  grp <- liftIO (c_EC_KEY_get0_group keyPtr)
    >>= nonNull (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_group returned NULL")
  pt <- liftIO (c_EC_KEY_get0_public_key keyPtr)
    >>= nonNull (OperationFailed "ecPublicKeyBytes: EC_KEY_get0_public_key returned NULL")
  -- POINT_CONVERSION_UNCOMPRESSED = 4
  -- First query the size by passing NULL buffer
  len <- liftIO $ c_EC_POINT_point2oct grp pt 4 nullPtr 0 nullPtr
  if len == 0
    then throwE (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct size query failed")
    else pure ()
  bsFptr <- liftIO $ BSI.mallocByteString (fromIntegral len)
  written <- liftIO $ withForeignPtr bsFptr $ \ptr ->
    c_EC_POINT_point2oct grp pt 4 (castPtr ptr) len nullPtr
  if written == 0
    then throwE (OperationFailed "ecPublicKeyBytes: EC_POINT_point2oct failed")
    else pure ()
  return (BSI.BS bsFptr (fromIntegral written))

-- | Get the private key as fixed-width big-endian bytes, zero-padded to the
-- full group order size. This avoids leaking information about the key value
-- through variable-length encoding and ensures compatibility with protocols
-- expecting fixed-width keys.
--
-- __Warning__: the result is an ordinary GC-managed 'ByteString' that is
-- never cleansed. Prefer 'ecPrivateKeySecureBytes'. (The underlying
-- @EC_KEY@ struct itself lives in BoringSSL-managed memory, which
-- BoringSSL zeroes on free.)
ecPrivateKeyBytes :: ECKeyPair -> IO (Either CryptoError ByteString)
ecPrivateKeyBytes (ECKeyPair _curve fptr) = withForeignPtr fptr $ \keyPtr -> runExceptT $ do
  grp <- liftIO (c_EC_KEY_get0_group keyPtr)
    >>= nonNull (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_group returned NULL")
  degree <- liftIO $ c_EC_GROUP_get_degree grp
  let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
  bn <- liftIO (c_EC_KEY_get0_private_key keyPtr)
    >>= nonNull (OperationFailed "ecPrivateKeyBytes: EC_KEY_get0_private_key returned NULL")
  bsFptr <- liftIO $ BSI.mallocByteString numBytes
  rc <- liftIO $ withForeignPtr bsFptr $ \ptr ->
    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) bn
  checkRC (OperationFailed "ecPrivateKeyBytes: BN_bn2bin_padded failed") rc
  return (BSI.BS bsFptr numBytes)

-- | Get the private key as fixed-width big-endian 'SecureBytes', zero-padded
-- to the full group order size. The memory will be zeroized on finalization.
-- Prefer this over 'ecPrivateKeyBytes' to avoid leaving private key material
-- in unprotected memory.
ecPrivateKeySecureBytes :: ECKeyPair -> IO (Either CryptoError SecureBytes)
ecPrivateKeySecureBytes (ECKeyPair _curve fptr) = withForeignPtr fptr $ \keyPtr -> runExceptT $ do
  grp <- liftIO (c_EC_KEY_get0_group keyPtr)
    >>= nonNull (OperationFailed "ecPrivateKeySecureBytes: EC_KEY_get0_group returned NULL")
  degree <- liftIO $ c_EC_GROUP_get_degree grp
  let numBytes = fromIntegral ((degree + 7) `div` 8) :: Int
  bn <- liftIO (c_EC_KEY_get0_private_key keyPtr)
    >>= nonNull (OperationFailed "ecPrivateKeySecureBytes: EC_KEY_get0_private_key returned NULL")
  ssSB <- liftIO $ createSecureBytes numBytes $ \_ -> return ()
  rc <- liftIO $ withSecureBytes ssSB $ \ptr _ ->
    c_BN_bn2bin_padded (castPtr ptr) (fromIntegral numBytes) bn
  checkRC (OperationFailed "ecPrivateKeySecureBytes: BN_bn2bin_padded failed") rc
  return ssSB

------------------------------------------------------------------------
-- Key import
------------------------------------------------------------------------

-- | Reconstruct an EC key pair from a curve and private key bytes.
ecKeyPairFromPrivateBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECKeyPair)
ecKeyPairFromPrivateBytes curve privBytes = withBoundThread $ mask_ $ runExceptT $ do
  liftIO clearBoringSSLError
  kp <- liftIO (c_EC_KEY_new_by_curve_name (curveNID curve))
    >>= nonNull (AllocationFailure "ecKeyPairFromPrivateBytes: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  ExceptT $ withForeignPtr fptr $ \k -> runExceptT $ do
    setPrivateKey k
    derivePublicKey k
    rc <- liftIO $ c_EC_KEY_check_key k
    checkRC (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_check_key failed") rc
  return (ECKeyPair curve fptr)
  where
    setPrivateKey kp = ExceptT $
      withByteString privBytes $ \privPtr privLen -> runExceptT $ do
        b <- liftIO (c_BN_bin2bn privPtr privLen nullPtr)
          >>= nonNull (AllocationFailure "ecKeyPairFromPrivateBytes: BN_bin2bn failed")
        rc <- liftIO $ c_EC_KEY_set_private_key kp b
        liftIO $ c_BN_clear_free b
        checkRC (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_private_key failed") rc

    derivePublicKey kp = do
      grp <- liftIO (c_EC_KEY_get0_group kp)
        >>= nonNull (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_group returned NULL")
      bn <- liftIO (c_EC_KEY_get0_private_key kp)
        >>= nonNull (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_get0_private_key returned NULL")
      pt <- liftIO (c_EC_POINT_new grp)
        >>= nonNull (AllocationFailure "ecKeyPairFromPrivateBytes: EC_POINT_new failed")
      flip finallyE (c_EC_POINT_free pt) $ do
        rc <- liftIO $ c_EC_POINT_mul grp pt bn nullPtr nullPtr nullPtr
        checkRC (OperationFailed "ecKeyPairFromPrivateBytes: EC_POINT_mul failed") rc
        rc2 <- liftIO $ c_EC_KEY_set_public_key kp pt
        checkRC (OperationFailed "ecKeyPairFromPrivateBytes: EC_KEY_set_public_key failed") rc2

-- | Parse an EC public key from uncompressed point bytes.
ecPublicKeyFromBytes :: ECCurve -> ByteString -> IO (Either CryptoError ECPublicKey)
ecPublicKeyFromBytes curve pubBytes = withBoundThread $ mask_ $ runExceptT $ do
  liftIO clearBoringSSLError
  kp <- liftIO (c_EC_KEY_new_by_curve_name (curveNID curve))
    >>= nonNull (AllocationFailure "ecPublicKeyFromBytes: EC_KEY_new_by_curve_name failed")
  fptr <- liftIO $ newForeignPtr c_EC_KEY_free_funptr kp
  ExceptT $ withForeignPtr fptr $ \k -> runExceptT $ do
    grp <- liftIO (c_EC_KEY_get0_group k)
      >>= nonNull (OperationFailed "ecPublicKeyFromBytes: EC_KEY_get0_group returned NULL")
    pt <- liftIO (c_EC_POINT_new grp)
      >>= nonNull (AllocationFailure "ecPublicKeyFromBytes: EC_POINT_new failed")
    flip finallyE (c_EC_POINT_free pt) $ ExceptT $
      withByteString pubBytes $ \bufPtr bufLen -> runExceptT $ do
        rc <- liftIO $ c_EC_POINT_oct2point grp pt bufPtr bufLen nullPtr
        checkRC (DecodeError "ecPublicKeyFromBytes: EC_POINT_oct2point failed") rc
        rc2 <- liftIO $ c_EC_KEY_set_public_key k pt
        checkRC (OperationFailed "ecPublicKeyFromBytes: EC_KEY_set_public_key failed") rc2
        rc3 <- liftIO $ c_EC_KEY_check_key k
        checkRC (DecodeError "ecPublicKeyFromBytes: EC_KEY_check_key failed (point not on curve)") rc3
  return (ECPublicKey fptr)

------------------------------------------------------------------------
-- Key extraction
------------------------------------------------------------------------

-- | Extract the public key from a key pair.
ecPublicKeyOfPair :: ECKeyPair -> IO (Either CryptoError ECPublicKey)
ecPublicKeyOfPair kp@(ECKeyPair curve _fptr) = runExceptT $ do
  pubBytes <- ExceptT $ ecPublicKeyBytes kp
  ExceptT $ ecPublicKeyFromBytes curve pubBytes
