{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Types we use in AAA.
-- We're keeping it simple and very-very compact.
module AAA.Types ( Accounts    (..)
                 , Account     (..)
                 , Permissions (..)
                 , Permission  (..)
                 , Session     (..)
                 , Sessions    (..)
                 , Variadic    (..)

                 , Hash        (..)
                 , Id          (..)
                 , Secret      (..)
                 , Salted      (..)
                 , Salt        (..)
                 , Token       (..)

                 , Error       (..)
                 , ErrorCode   (..)

                 , PermissionChecker (..)
                 ) where

import           Data.ByteString ( ByteString() )
import           Data.Time.Clock.POSIX ( POSIXTime() )
import           Data.String

import qualified Data.Map      as M
import qualified Data.Text     as T

-- | Hash is just a ByteString. Everything Hash-related is found in
-- AAA.Crypto. TODO: Create a type-family based library for different
-- pluggable cryptography implementations.
type Hash      = ByteString

-- | Salt is just a ByteString. We wrap it in newtype to reduce the
-- probability of mistakenly shoving a random thing 
newtype Salt   = Salt { getSalt :: ByteString }
  deriving (Eq, IsString, Read, Show, Ord)

-- | Phantom type to enforce that ID of a certain type can't be used
-- to index another type.
newtype Id a   = Id { getId :: T.Text } deriving ( Eq
                                                 , IsString
                                                 , Read
                                                 , Show
                                                 , Ord )

-- | Type which captures secrets. We should never store a secret, instead
-- we should store Salted version of the Secret.
newtype Secret = Secret { getSecret :: T.Text } deriving (Eq, Ord, IsString, Read, Show)

-- | Type which captures tokens. Once session for some class of actions is
-- established, every request shall use last received Token and every response
-- shall provide the new Token to be used for this session.
newtype Token  = Token { getToken :: Hash }   deriving (Eq, Ord, IsString, Read, Show)

-- | Type which captures the concept of a hash being salted.
newtype Salted = Salted { getSalted :: Hash }   deriving (Eq, IsString, Read, Show, Ord)

-- | Record type for accounting. It stores information about how
-- to authenticate this account and which classes of actions does
-- this particular account is authorized to perform.
data Account = Account { aaaAct_name        :: Id Account
                       , aaaAct_salted      :: Salted
                       , aaaAct_permissions :: Permissions }
  deriving (Eq, Ord, Read, Show)
 
-- | Id Account → Account mapping.
type Accounts = M.Map (Id Account) Account

-- | Record type for authorization. It stores information about
-- a single permission.
data Permission = Permission { aaaPerm_name   :: Id Permission
                             , aaaPerm_value  :: Variadic }
  deriving (Eq, Ord, Read, Show)

-- | Id Permission →  Permission mapping.
type Permissions = M.Map (Id Permission) Permission

-- | Permission checker function type
type PermissionChecker = Id Permission -> Id Account -> Accounts -> Bool

-- | A very simple variadic data type. It should be enough for the
-- purposes of keeping track of any imaginable permission type.
-- There is no separate sub-type for a lot of stuff, like Bitmask
-- or, G-d forbid, JSON, but with some imagination and convenience
-- wrappers, you can emulate whatever you want with this Variadic type.
data Variadic = VI Int
              | VB Bool
              | VT T.Text
              | VR Rational
              | VV [Variadic]
              | VM (M.Map Variadic Variadic)
              | VU ()
  deriving (Eq, Ord, Read, Show)

-- | Record type which stores information about a given session
-- in one client, performing class of actions optionally specified
-- with `Id Permission`. In case you don't need such a degree of
-- authorization granularity, just make a value of Permission typw
-- which captures all the action classes and use it in your `Session`s.
data Session = Session { aaaSess_name       :: Id Session
                       , aaaSess_permission :: Id Permission
                       , aaaSess_account    :: Id Account
                       , aaaSess_token      :: Token
                       , aaaSess_time       :: POSIXTime }
  deriving (Eq, Ord, Show)

-- | Id Session → Session mapping.
type Sessions = M.Map (Id Account, Id Session, Id Permission) Session

-- | Error type
newtype Error = Error { getError :: (ErrorCode, T.Text) } deriving (Eq, Read, Show)

-- | Error codes as a union type
data ErrorCode = EAccountAlreadyRegistered
               | EAccountNotFound
               | EIncorrectPassword
               | EPermissionDenied
               | ESessionExists
               | ESessionNotFound
               | ETokenMismatch
               | ESessionExistenceMismatch
               | EAuth
  deriving (Eq, Read, Show)
