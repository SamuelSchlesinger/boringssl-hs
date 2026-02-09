module Crypto.BoringSSL.Internal.ExceptT
  ( ExceptT(..)
  , throwE
  , liftIO
  ) where

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
