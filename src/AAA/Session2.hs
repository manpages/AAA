{-# LANGUAGE OverloadedStrings #-}

-- | Functions to update session table and token chains.

module AAA.Session2 ( tick' ) where

import AAA.Session
import AAA.Types

import qualified AAA.Account as A
import qualified AAA.Crypto as C

import qualified Data.ByteString as BS
import           Data.Maybe (isJust, fromJust)
import qualified Data.Map as M
import qualified Data.Text as T
import           Data.Time.Clock.POSIX ( POSIXTime(), getPOSIXTime )

import           OpenSSL.Random ( randBytes )

type IOE a b = IO (Either a b)
type PC      = PermissionChecker
type M a     = Maybe a

-- | Improved version of tick from AAA.Session
tick' :: Salt -> PC -> Req -> (() -> a) -> IOE Error (Resp a)
tick' z e r@Req { aaaSReq_account    = account
                , aaaSReq_auth       = Left auth
                , aaaSReq_session    = session
                , aaaSReq_permission = permission
                , aaaSReq_sessions   = sessions
                , aaaSReq_accounts   = accounts } g =
  tick'Do r g ((not . sex) r) (secretMatches z r) (pc e r) (initToken r) Nothing

tick' z e r@Req { aaaSReq_account    = account
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
