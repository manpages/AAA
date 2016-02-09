{-# LANGUAGE OverloadedStrings #-}

-- | Functions to update accounting table.
module AAA.Account ( addAccount
                   , getPermissions
                   , permit
                   , secretMatches ) where

import           AAA.Types 
import qualified AAA.Crypto as C

import qualified Data.Map   as M
import qualified Data.Text  as T

import           Data.Maybe (fromJust)

type E a b = Either a b

-- | Gets an explicit `Salt`; tuple of `Id Account`, `Secret`; and current registry
-- of `Accounts` and returns `Either (Account, Accounts) Error`.
--
-- ```
-- Example: 
-- addAccount (Id "artosis", Secret "pylon", Salt "menzoberranzan") M.empty
-- > Left ( Account { aaaAct_name = Id {getId = "artosis"}
--                  , aaaAct_salted = Salted {getSalted = "gR0MteJb6J8+CIA9AhGd4juJr3S2rKhYwws4gA+vKEU="}
--                  , aaaAct_permissions = fromList [] }
--        , fromList [ ( Id {getId = "sweater"}
--                     , Account { aaaAct_name = Id {getId = "artosis"}, 
--                                 *snip* } ) ] )
-- ```
addAccount :: Salt -> (Id Account, Secret) -> Accounts -> E (Account, Accounts) Error
addAccount s a@(x, _) xs
  | M.lookup x xs == Nothing = Left  $ addAccountDo s a xs
  | True                     = Right $ Error ( EAccountAlreadyRegistered
                                             , T.unwords [ "Account"
                                                         , (getId x)
                                                         , "is already registered" ] )

-- | Returns `Maybe Permissions` of an account by `Id Account`
getPermissions :: Id Account -> Accounts -> Maybe Permissions
getPermissions x xs
  | y == Nothing = Nothing
  | True         = Just $ aaaAct_permissions $ fromJust y
  where
    y = M.lookup x xs

-- | Authorizes (permits) a certain account to do some classes of actions.
-- Takes `Id Account`, `Permissions`, and `Accounts` and *adds* given `Permissions`
-- to the current `Permissions` map of this `Account`.
-- Gives back either updated version of `Account` along with updated `Accounts`, or `Error`.
permit :: Id Account -> Permissions -> Accounts -> E (Account, Accounts) Error
permit x ps xs = permitDo x (M.lookup x xs) ps xs

addAccountDo :: Salt -> (Id Account, Secret) -> Accounts -> (Account, Accounts)
addAccountDo z (x, y) xs =
  (acc, M.insert x acc xs)
  where
    acc = Account { aaaAct_name        = x
                  , aaaAct_salted      = C.saltBinary (getSecret y) z
                  , aaaAct_permissions = M.empty }

permitDo :: Id Account -> Maybe Account -> Permissions -> Accounts -> E (Account, Accounts) Error
permitDo x (Just acc0) ps xs =
  Left (acc, M.update (const $ Just acc) x xs)
  where
    acc = acc0 { aaaAct_permissions = M.union ps ps0 }
    ps0 = aaaAct_permissions acc0
permitDo _ _ _ _ = Right $ Error ( EAccountNotFound
                                 , "Requested account does not exist" )

-- | Check if Secret matches stored Salted hash.
secretMatches :: Salt -> Secret -> Id Account -> Accounts -> Bool
secretMatches z (Secret s) x xs
  | y == Nothing = False
  | True         = C.saltBinary s z == g y
  where
    y          = M.lookup x xs
    g (Just a) = aaaAct_salted a
