-- | SPAKE2 password-authenticated key exchange.
--
-- Allows two parties sharing a password to agree on a shared key.
-- An attacker can only test one password guess per protocol execution.
module Crypto.BoringSSL.SPAKE2
  ( -- * Types
    Role(..)
  , SPAKE2Ctx
    -- * Protocol
  , newContext
  , generateMessage
  , processMessage
    -- * Secure memory
  , SecureBytes
  , secureBytesToByteString
  , secureBytesLength
    -- * Error type
  , CryptoError(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import Foreign.Storable
import Control.Exception (mask_)
import Control.Concurrent.MVar

import Crypto.BoringSSL.Internal.Buffer
import Crypto.BoringSSL.Internal.Error
import Crypto.BoringSSL.Internal.FFI.SPAKE2
import Crypto.BoringSSL.Internal.SecureBytes

-- | The role in a SPAKE2 exchange. The two parties must use different roles.
data Role = Alice | Bob
  deriving (Eq, Show)

-- | A SPAKE2 context. Each context must be used for exactly one exchange.
-- Thread-safe: concurrent calls are serialized via an internal lock.
data SPAKE2Ctx = SPAKE2Ctx !(MVar ()) !(ForeignPtr SPAKE2_CTX)

roleToC :: Role -> CInt
roleToC Alice = spake2RoleAlice
roleToC Bob   = spake2RoleBob

-- | Create a new SPAKE2 context. @myName@ and @theirName@ are optional
-- identity strings that are bound into the protocol.
newContext :: Role -> ByteString -> ByteString -> IO (Either CryptoError SPAKE2Ctx)
newContext role myName theirName = mask_ $
  withByteString myName $ \myNamePtr myNameLen ->
    withByteString theirName $ \theirNamePtr theirNameLen -> do
      ctx <- c_SPAKE2_CTX_new (roleToC role) myNamePtr myNameLen
               theirNamePtr theirNameLen
      if ctx == nullPtr
        then return (Left (AllocationFailure "newContext: SPAKE2_CTX_new failed"))
        else do
          fptr <- newForeignPtr c_SPAKE2_CTX_free_funptr ctx
          lock <- newMVar ()
          return (Right (SPAKE2Ctx lock fptr))

-- | Generate a SPAKE2 message from a password. Call once per context.
-- The resulting message should be sent to the peer.
-- Thread-safe: concurrent calls are serialized.
generateMessage :: SPAKE2Ctx -> ByteString -> IO (Either CryptoError ByteString)
generateMessage (SPAKE2Ctx lock fptr) password =
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> do
    let maxOut = spake2MaxMsgSize
    outFPtr <- BSI.mallocByteString maxOut
    alloca $ \outLenPtr -> do
      rc <- withForeignPtr outFPtr $ \outPtr ->
        withByteString password $ \pwPtr pwLen ->
          c_SPAKE2_generate_msg ctx (castPtr outPtr) outLenPtr
            (fromIntegral maxOut) pwPtr pwLen
      if rc /= 1
        then return (Left (OperationFailed "generateMessage: SPAKE2_generate_msg failed"))
        else do
          actualLen <- peek outLenPtr
          return (Right (BSI.BS outFPtr (fromIntegral actualLen)))

-- | Process the peer's SPAKE2 message and derive the shared key.
-- Call once per context, after 'generateMessage'.
-- Returns 'Left' if the message is invalid.
-- Thread-safe: concurrent calls are serialized.
processMessage :: SPAKE2Ctx -> ByteString -> IO (Either CryptoError SecureBytes)
processMessage (SPAKE2Ctx lock fptr) theirMsg =
  withMVar lock $ \_ ->
  withForeignPtr fptr $ \ctx -> do
    let maxOut = spake2MaxKeySize
    sb <- createSecureBytes maxOut $ \_ -> return ()
    alloca $ \outLenPtr -> do
      rc <- withSecureBytes sb $ \outPtr _ ->
        withByteString theirMsg $ \msgPtr msgLen ->
          c_SPAKE2_process_msg ctx (castPtr outPtr) outLenPtr
            (fromIntegral maxOut) msgPtr msgLen
      if rc /= 1
        then return (Left (OperationFailed "processMessage: SPAKE2_process_msg failed"))
        else do
          actualLen <- fromIntegral <$> peek outLenPtr
          if actualLen == maxOut
            then return (Right sb)
            else do
              -- Trim to actual key length
              trimmed <- createSecureBytes actualLen $ \dstPtr ->
                withSecureBytes sb $ \srcPtr _ ->
                  Foreign.Marshal.Utils.copyBytes (castPtr dstPtr) (castPtr srcPtr) actualLen
              return (Right trimmed)
