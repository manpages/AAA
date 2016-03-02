-- | Convenience functions to work with Permissions

module AAA.Permission ( updatePermissions
                      , fromList ) where

import qualified Data.Map as M

import           AAA.Types

-- | Make Permissions from a list of Permission
fromList :: [Permission] -> Permissions
fromList = M.fromList . map (\p -> (aaaPerm_name p, p))

-- | Update Permissions for a user Account
updatePermissions :: Id Account -> Permissions -> Accounts -> Maybe Accounts
updatePermissions a ps as = updatePermissionsDo a ps as (M.lookup a as)

updatePermissionsDo :: Id Account -> Permissions -> Accounts -> Maybe Account -> Maybe Accounts
updatePermissionsDo _ _  _  Nothing = Nothing
updatePermissionsDo _ ps as ( Just Account { aaaAct_name   = name
                                           , aaaAct_salted = salted } ) =
  Just $ M.update (const $ Just acc) name as
  where
    acc = Account { aaaAct_name         = name
                  , aaaAct_salted       = salted
                  , aaaAct_permissions  = ps } 
