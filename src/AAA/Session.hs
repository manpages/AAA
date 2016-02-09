{-# LANGUAGE OverloadedStrings #-}

-- | Functions to update session table and token chains.
module AAA.Session ( tick, sessionExists ) where

import AAA.Types
import AAA.Account

import qualified AAA.Crypto as C

import qualified Data.ByteString as BS
import           Data.Maybe (isJust, fromJust)
import qualified Data.Map as M
import qualified Data.Text as T
import           Data.Time.Clock.POSIX ( POSIXTime(), getPOSIXTime )

import           OpenSSL.Random ( randBytes )

type Auth    = Either Secret Token
type IOE a b = IO (Either a b)
type PC      = PermissionChecker
type M a     = Maybe a

-- | Gets a session key (Id Account, Id Session, Id Permission); 
-- and Sessions, and gives back information if such session exists.
sessionExists :: (Id Account, Id Session, Id Permission) -> Sessions -> Bool
sessionExists k kvs = isJust $ M.lookup k kvs
 
tick :: Salt                        ->
        PC                          ->
        (Id Account, Auth)          ->
        (Id Session, Id Permission) ->
        (Sessions, Accounts)        ->
        IOE (M POSIXTime, Session, Sessions) Error
tick z f (x, Left p) s b@(ss, xs)
  | secretMatches z p x xs = initializeSession f x s b
  | True                   = return $ Right $ Error (EIncorrectPassword, "Incorrect password")
  where
    acc = M.lookup x xs

initializeSession :: PC                          ->
                     Id Account                  ->
                     (Id Session, Id Permission) ->
                     (Sessions, Accounts)        ->
                     IOE (M POSIXTime, Session, Sessions) Error
initializeSession f x (session, permission) (sessions, accounts)
  | sessionExists (x, session, permission) sessions = (return . Right . Error) initErr
  | True                                            = initializeSessionDo f (x, session, permission) (sessions, accounts)
  where
    initErr = ( ESessionExists
              , T.unwords [ "Session for", (pshow x), "at", (pshow session)
                          , "for class of actions", (pshow permission)
                          , "already exists. MITM / replay attempt possible." ] )

initializeSessionDo :: PC                                      ->
                       (Id Account, Id Session, Id Permission) ->
                       (Sessions, Accounts)                    ->
                       IOE (M POSIXTime, Session, Sessions) Error
initializeSessionDo f a@(x, session, permission) (sessions, accounts)
  | f permission x accounts = initializeSessionFinally a (sessions, accounts)
  | True                    = (return . Right . Error) permError
  where
    permError = ( EPermissionDenied
                , T.unwords [ "Permission denied for", (pshow x), "to perform", (pshow permission), "at"
                            , (pshow session), ". Endpoint enumeration attack possible." ] )

initializeSessionFinally :: (Id Account, Id Session, Id Permission) -> 
                            (Sessions, Accounts)                    ->
                            IOE (M POSIXTime, Session, Sessions) Error
initializeSessionFinally a@(x, session, permission) (sessions, accounts) = do
  tau      <- getPOSIXTime 
  noise    <- randBytes 32
  let tok   = (C.hash . BS.append noise . getSalted) (aaaAct_salted acc)
  let s1    = mkSession tok tau
  return $ Left (Nothing, s1, sessions1 s1)
  where
    mkSession t q = Session { aaaSess_name       = session
                            , aaaSess_permission = permission
                            , aaaSess_account    = x
                            , aaaSess_time       = q
                            , aaaSess_token      = t }
    sessions1 s = M.update (const $ Just s) a sessions
    acc = fromJust $ M.lookup x accounts

pshow :: (Show a) => a -> T.Text
pshow = (T.pack . show)
