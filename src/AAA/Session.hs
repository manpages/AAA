{-# LANGUAGE OverloadedStrings #-}

-- | Functions to update session table and token chains.
module AAA.Session ( tick
                   , invalidate
                   , logout
                   , sessionExists
                   , terminate

                   , Auth(..)
                   , Req(..)
                   , Resp(..) ) where

import AAA.Types

import qualified AAA.Account as A
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
  deriving (Eq, Ord, Show)

data Resp a = Resp { aaaSResp_lastSeen :: Maybe POSIXTime
                   , aaaSResp_time     :: POSIXTime
                   , aaaSResp_session  :: Session
                   , aaaSResp_sessions :: Sessions
                   , aaaSResp_value    :: a }

-- | Gets a session key (Id Account, Id Session, Id Permission),
-- and Sessions; and gives back information if such session exists.
sessionExists :: (Id Account, Id Session, Id Permission) -> Sessions -> Bool
sessionExists k kvs = isJust $ M.lookup k kvs

-- | Invalidate all sessions with last tick older than given DiffTime
-- as POSIXTime (eg. `5 :: POSIXTime -- 5s`).
invalidate :: POSIXTime -> Sessions -> IO Sessions
invalidate delta sessions = do
  tau <- getPOSIXTime
  return $ M.filter (f tau) sessions
  where
    f t session = (t - (aaaSess_time session)) < delta 

-- | Terminate session with the given key
terminate :: (Id Account, Id Session, Id Permission) -> Sessions -> Sessions
terminate = M.delete

-- | Authenticated logout function, terminates all sessions that match pair
-- `(Id Account, Id Session)`.
logout :: Req -> IOE Error (Resp ())
logout r@Req { aaaSReq_account     = account
             , aaaSReq_session     = session
             , aaaSReq_auth        = Right token
             , aaaSReq_sessions    = sessions
             , aaaSReq_accounts    = accounts }
  | token == aaaSess_token theSession = do
      tau <- getPOSIXTime
      return $ Right $ logoutDo tau
  | True =
      return $ Left $ Error (ETokenMismatch, "Token mismatch.")
  where
    theSession = snd $ fromJust $ M.lookupGE (account, session, Id "") sessions
    sessions1 = M.filterWithKey g sessions
    g (a, s, _) _
      | a == account && s == session = False
      | True                         = True
    logoutDo t = Resp { aaaSResp_lastSeen   = Just $ aaaSess_time theSession
                      , aaaSResp_time       = t
                      , aaaSResp_session    = theSession
                      , aaaSResp_sessions   = sessions1
                      , aaaSResp_value      = () }
logout _ = return $ Left $ Error (EPermissionDenied, "Logging out as the first action of a session doesn't make sense.")

{--
-- | Login function. Takes `(Id Account, Id Session)` and returns a `Resp` per
-- Id Permission, starting the sessions.
login :: Salt -> PC -> Req -> IOE Error M.Map (Id Permission) Resp
-- TODO: move @gromak's login function here
--}

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
-- this library using a `Left Error` value (wrapped in IO in this particular case).
tick :: Salt -> PC -> Req -> (() -> a) -> IOE Error (Resp a)
tick z e r@Req { aaaSReq_account    = account
                , aaaSReq_auth       = Left auth
                , aaaSReq_session    = session
                , aaaSReq_permission = permission
                , aaaSReq_sessions   = sessions
                , aaaSReq_accounts   = accounts } g =
  tick'Do r g ((not . sex) r) (secretMatches z r) (pc e r) (initToken r) Nothing

tick z e r@Req { aaaSReq_account    = account
                , aaaSReq_auth       = Right auth
                , aaaSReq_session    = session
                , aaaSReq_permission = permission
                , aaaSReq_sessions   = sessions
                , aaaSReq_accounts   = accounts } g =
  tick'Do r g (sex r) (tokenMatches r) (pc e r) (contToken r) (justSessTime r)

tick'Do r _ False _ _ _ _ =
  return $ Left $ Error (ESessionExistenceMismatch, tshow r)
tick'Do r _ _ False _ _ _ =
  return $ Left $ Error (EAuth, tshow r)
tick'Do r _ _ _ False _ _ =
  return $ Left $ Error (EPermissionDenied, tshow r)
tick'Do r g True True True token1 tau0 = do
  tau <- getPOSIXTime
  t1  <- token1
  let session1 = mkSession t1 tau r
  return $ Right $ Resp { aaaSResp_lastSeen = tau0
                        , aaaSResp_time     = tau
                        , aaaSResp_session  = session1
                        , aaaSResp_sessions = mkSessions session1 r
                        , aaaSResp_value    = g () }

mkSessions :: Session -> Req -> Sessions
mkSessions s@Session { aaaSess_name       = sid
                     , aaaSess_account    = aid
                     , aaaSess_permission = pid } Req { aaaSReq_sessions = sessions } =
  f (M.member (aid, sid, pid) sessions) (aid, sid, pid) s sessions
  where
    f True  k x y = M.update (const $ Just x) k y
    f False k x y = M.insert k x y

mkSession :: Token -> POSIXTime -> Req -> Session
mkSession tok tau Req { aaaSReq_account     = account
                      , aaaSReq_session     = session
                      , aaaSReq_permission  = permission } =
  Session { aaaSess_name        = session
          , aaaSess_account     = account
          , aaaSess_permission  = permission
          , aaaSess_time        = tau
          , aaaSess_token       = tok }

sex :: Req -> Bool
sex Req { aaaSReq_account     = a
        , aaaSReq_session     = s
        , aaaSReq_permission  = p
        , aaaSReq_sessions    = ss } =
  M.member (a, s, p) ss

secretMatches :: Salt -> Req -> Bool
secretMatches z Req { aaaSReq_account   = a
                    , aaaSReq_accounts  = as
                    , aaaSReq_auth      = Left s } =
  A.secretMatches z s a as

tokenMatches :: Req -> Bool
tokenMatches r@Req { aaaSReq_auth = Right t } =
  t == (aaaSess_token $ partialSession r)

initToken :: Req -> IO Token
initToken r = do
  noise <- randBytes 32
  return $ Token $ (C.hash . BS.append noise) . (getSalted . aaaAct_salted) $ partialAccount r

contToken :: Req -> IO Token
contToken r = do
  noise <- randBytes 32
  return $ Token $ (C.hash . BS.append noise) . (getToken . aaaSess_token) $ partialSession r

partialSession :: Req -> Session
partialSession Req { aaaSReq_account     = a
                   , aaaSReq_session     = s
                   , aaaSReq_permission  = p
                   , aaaSReq_sessions    = ss } =
  fromJust $ M.lookup (a, s, p) ss

partialAccount :: Req -> Account
partialAccount Req { aaaSReq_account   = a
                   , aaaSReq_accounts  = as } =
  fromJust $ M.lookup a as

pc :: PC -> Req -> Bool
pc e Req { aaaSReq_permission = p
         , aaaSReq_account    = a
         , aaaSReq_accounts   = as } =
  e p a as

justSessTime :: Req -> Maybe POSIXTime
justSessTime r =
  Just $ aaaSess_time $ partialSession r

tshow :: (Show a) => a -> T.Text
tshow = (T.pack . show)
