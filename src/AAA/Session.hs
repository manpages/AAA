{-# LANGUAGE OverloadedStrings #-}

-- | Functions to update session table and token chains.
module AAA.Session ( tick
                   , sessionExists

                   , Auth(..)
                   , Req(..)
                   , Resp(..) ) where

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

data Req = Req { aaaSReq_account     :: Id Account
               , aaaSReq_auth        :: Auth
               , aaaSReq_session     :: Id Session
               , aaaSReq_permission  :: Id Permission
               , aaaSReq_accounts    :: Accounts
               , aaaSReq_sessions    :: Sessions }

data Resp = Resp { aaaSResp_lastSeen :: Maybe POSIXTime
                 , aaaSResp_session  :: Session
                 , aaaSResp_sessions :: Sessions }

-- | Gets a session key (Id Account, Id Session, Id Permission),
-- and Sessions; and gives back information if such session exists.
sessionExists :: (Id Account, Id Session, Id Permission) -> Sessions -> Bool
sessionExists k kvs = isJust $ M.lookup k kvs

-- | Along every request to perform action of class `Id Permission`, either
-- Left Secret (if the session is about to get initialized), or Right Token
-- (if session for that device / client, class of actions, and user is already
-- initialized and is continued) should be sent.
--
-- State of Accounts storage and Sessions storage should be given to this function
-- as well.
--
-- It all is enclosed within the request record `Req` of this module.
--
-- This function first authorizes the user based on authentication method provided
-- (either Secret, or Token), then it checks if the user is authorized to perforn
-- actions of this class using PermissionChecker function, supplied to this function
-- as the second argument, and finally it bumps the token chain, returning response
-- record `Resp` of this module, which has information about the last POSIXTime
-- this token chain was bumped before this one (`aaaSResp_lastSeen`), regenerated
-- session (`aaaSResp_sessions`), and the updated Session storage (`aaaSResp_sessions`).
--
-- Response is wrapped in IO Either and error is reported, like everywhere else in
-- this library using a `Right Error` value (wrapped in IO in this particular case).
tick :: Salt -> PC -> Req -> IOE Resp Error
--tick z f (x, Left p) s b@(ss, xs)
tick z f r@Req { aaaSReq_account    = account
               , aaaSReq_auth       = Left secret
               , aaaSReq_session    = session
               , aaaSReq_permission = permission
               , aaaSReq_sessions   = sessions
               , aaaSReq_accounts   = accounts }
  | secretMatches z secret account accounts = initializeSession f r
  | True                                    = return $ Right $ Error ( EIncorrectPassword
                                                                     , "Incorrect password")
{-- tick z f r@Req { aaaSReq_account    = account
               , aaaSReq_auth       = Right token
               , aaaSReq_session    = session
               , aaaSReq_permission = permission
               , aaaSReq_sessions   = sessions
               , aaaSReq_accounts   = accounts }
  | sessionExists (account, session, permission) sessions =
      bumpToken ???
  | True = 
      return $ Right $ Error ( ESessionNotFound
                             , T.unwords [ "User", (tshow account)
                                         , "attempted to keep a non-existing"
                                         , (show p) "session alive at"
                                         , (show s) ] )
--}

initializeSession :: PC -> Req -> IOE Resp Error
initializeSession f r@Req { aaaSReq_account    = account
                          , aaaSReq_auth       = Left secret
                          , aaaSReq_session    = session
                          , aaaSReq_permission = permission
                          , aaaSReq_sessions   = sessions
                          , aaaSReq_accounts   = accounts }
  | sessionExists (account, session, permission) sessions =
      (return . Right . Error) initErr
  | True =
      initializeSessionDo f r
  where
    initErr = ( ESessionExists
              , T.unwords [ "Session for", (tshow account), "at", (tshow session)
                          , "for class of actions", (tshow permission)
                          , "already exists. MITM / replay attempt possible." ] )

initializeSessionDo :: PC -> Req -> IOE Resp Error
initializeSessionDo f r@Req { aaaSReq_account    = account
                            , aaaSReq_auth       = Left secret
                            , aaaSReq_session    = session
                            , aaaSReq_permission = permission
                            , aaaSReq_sessions   = sessions
                            , aaaSReq_accounts   = accounts }
  | f permission account accounts =
      initializeSessionFinally r
  | True =
      (return . Right . Error) permError
  where
    permError = ( EPermissionDenied
                , T.unwords [ "Permission denied for", (tshow account)
                            , "to perform", (tshow permission)
                            , "at", (tshow session)
                            , ". Endpoint enumeration attack possible." ] )

initializeSessionFinally :: Req -> IOE Resp Error
initializeSessionFinally r@Req { aaaSReq_account    = account
                               , aaaSReq_auth       = Left secret
                               , aaaSReq_session    = session
                               , aaaSReq_permission = permission
                               , aaaSReq_sessions   = sessions
                               , aaaSReq_accounts   = accounts } = do
  tau      <- getPOSIXTime 
  noise    <- randBytes 32
  let tok   = (C.hash . BS.append noise . getSalted) (aaaAct_salted acc)
  let s1    = mkSession tok tau
  return $ Left $ response s1
  where
    mkSession t q = Session { aaaSess_name       = session
                            , aaaSess_permission = permission
                            , aaaSess_account    = account
                            , aaaSess_time       = q
                            , aaaSess_token      = t }
    sessions1 s = M.update (const $ Just s) (account, session, permission) sessions
    acc = fromJust $ M.lookup account accounts
    response s = Resp { aaaSResp_lastSeen = Nothing
                      , aaaSResp_session  = s
                      , aaaSResp_sessions = sessions1 s }

tshow :: (Show a) => a -> T.Text
tshow = (T.pack . show)
