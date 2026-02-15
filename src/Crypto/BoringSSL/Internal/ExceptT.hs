module Crypto.BoringSSL.Internal.ExceptT
  ( ExceptT(..)
  , throwE
  , liftIO
  , nonNull
  , checkRC
  , checkRCError
  , bracketE
  , finallyE
  , maskE_
  , allocaE
  ) where

import Control.Exception (mask_, finally, bracket)
import Foreign.C.Types
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr
import Foreign.Storable

import Crypto.BoringSSL.Internal.Error

-- | A minimal ExceptT monad transformer, defined locally to avoid
-- a dependency on transformers/mtl.
newtype ExceptT e m a = ExceptT { runExceptT :: m (Either e a) }

instance Functor m => Functor (ExceptT e m) where
  fmap f (ExceptT m) = ExceptT (fmap (fmap f) m)

instance Monad m => Applicative (ExceptT e m) where
  pure = ExceptT . pure . Right
  ExceptT mf <*> ExceptT ma = ExceptT $ do
    ef <- mf
    case ef of
      Left e -> return (Left e)
      Right f -> do
        ea <- ma
        case ea of
          Left e  -> return (Left e)
          Right a -> return (Right (f a))

instance Monad m => Monad (ExceptT e m) where
  ExceptT m >>= f = ExceptT $ do
    ea <- m
    case ea of
      Left e  -> return (Left e)
      Right a -> runExceptT (f a)

-- | Throw an error.
throwE :: Monad m => e -> ExceptT e m a
throwE = ExceptT . return . Left

-- | Lift an IO action into ExceptT.
liftIO :: IO a -> ExceptT e IO a
liftIO = ExceptT . fmap Right

-- | Check that a pointer is non-null, throwing the given error if it is.
nonNull :: Ptr a -> CryptoError -> ExceptT CryptoError IO (Ptr a)
nonNull p err
  | p == nullPtr = throwE err
  | otherwise    = pure p

-- | Check that a C return code is 1 (success), throwing the given error otherwise.
checkRC :: CInt -> CryptoError -> ExceptT CryptoError IO ()
checkRC 1 _ = pure ()
checkRC _ err = throwE err

-- | Check that a C return code is 1 (success), consulting the BoringSSL
-- error queue on failure and using the given string as fallback.
checkRCError :: CInt -> String -> ExceptT CryptoError IO ()
checkRCError 1 _ = pure ()
checkRCError _ ctx = ExceptT $ do
  merr <- getBoringSSLError
  return (Left (maybe (OperationFailed ctx) id merr))

-- | Resource management: acquire, release, use within ExceptT.
bracketE :: IO a -> (a -> IO ()) -> (a -> ExceptT e IO b) -> ExceptT e IO b
bracketE acquire release use = ExceptT $
  bracket acquire release (runExceptT . use)

-- | Ensure a cleanup action runs after an ExceptT computation.
finallyE :: ExceptT e IO a -> IO () -> ExceptT e IO a
finallyE (ExceptT m) cleanup = ExceptT (m `finally` cleanup)

-- | Run an ExceptT computation with async exceptions masked.
maskE_ :: ExceptT e IO a -> ExceptT e IO a
maskE_ (ExceptT m) = ExceptT (mask_ m)

-- | Bridge alloca into ExceptT (CPS style).
allocaE :: Storable a => (Ptr a -> ExceptT e IO b) -> ExceptT e IO b
allocaE f = ExceptT $ alloca $ \p -> runExceptT (f p)
