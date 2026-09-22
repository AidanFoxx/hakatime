{-# LANGUAGE OverloadedStrings #-}

module Haka.Middleware.CSRF
  ( csrfProtection,
    CSRFConfig (..),
    defaultCSRFConfig,
  )
where

import Control.Monad.IO.Class (liftIO)
import Data.ByteString.Base64 (encode)
import qualified Data.ByteString as BS
import Data.CaseInsensitive (CI, mk)
import Network.HTTP.Types (Header, hContentType, status403)
import Network.Wai
  ( Application,
    Middleware,
    Request,
    Response,
    modifyResponse,
    vault,
  )
import Network.Wai.Internal (Request (..), ResponseReceived)
import qualified Network.Wai.Parse as Parse
import System.Random (randomRIO)

-- | CSRF configuration.
data CSRFConfig = CSRFConfig
  { -- | Name of the CSRF token cookie.
    csrfCookieName :: BS.ByteString,
    -- | Name of the CSRF token header.
    csrfHeaderName :: CI BS.ByteString,
    -- | Paths that are exempt from CSRF protection (e.g., API endpoints).
    csrfExemptPaths :: [BS.ByteString],
    -- | Whether to use SameSite=Strict for cookies.
    csrfSameSiteStrict :: Bool,
    -- | Cookie path.
    csrfCookiePath :: BS.ByteString
  }

-- | Default CSRF configuration.
-- Heartbeat endpoints are exempt as they use API token authentication.
defaultCSRFConfig :: CSRFConfig
defaultCSRFConfig =
  CSRFConfig
    { csrfCookieName = "csrf_token",
      csrfHeaderName = mk "X-CSRF-Token",
      csrfExemptPaths = 
        [ "/api/v1/users/current/heartbeats",
          "/api/v1/users/current/heartbeats.bulk"
        ],
      csrfSameSiteStrict = True,
      csrfCookiePath = "/"
    }

-- | Generate a random CSRF token (32 bytes).
generateCSRFToken :: IO BS.ByteString
generateCSRFToken = BS.pack <$> sequence [randomRIO (0, 255) | _ <- [1 .. 32]]

-- | Check if a path is exempt from CSRF protection.
isExemptPath :: CSRFConfig -> BS.ByteString -> Bool
isExemptPath config path = path `elem` csrfExemptPaths config

-- | Check if the request method is safe (GET, HEAD, OPTIONS).
isSafeMethod :: Request -> Bool
isSafeMethod req =
  case requestMethod req of
    "GET" -> True
    "HEAD" -> True
    "OPTIONS" -> True
    _ -> False

-- | Get CSRF token from request cookies.
getCSRFTokenFromCookie :: CSRFConfig -> Request -> Maybe BS.ByteString
getCSRFTokenFromCookie config req =
  case lookup "Cookie" (requestHeaders req) of
    Just cookieHeader -> do
      let cookies = Parse.parseCookiesText $ decodeUtf8 cookieHeader
      lookup (csrfCookieName config) cookies
    Nothing -> Nothing

-- | Get CSRF token from request header.
getCSRFTokenFromHeader :: CSRFConfig -> Request -> Maybe BS.ByteString
getCSRFTokenFromHeader config req = lookup (csrfHeaderName config) (requestHeaders req)

-- | Validate CSRF token by comparing cookie and header values.
validateCSRF :: CSRFConfig -> Request -> Bool
validateCSRF config req =
  case (getCSRFTokenFromCookie config req, getCSRFTokenFromHeader config req) of
    (Just cookieToken, Just headerToken) -> cookieToken == headerToken
    _ -> False

-- | CSRF protection middleware.
-- For state-changing requests (POST, PUT, DELETE, PATCH):
--   - Validates that X-CSRF-Token header matches the csrf_token cookie
-- For safe requests (GET, HEAD, OPTIONS):
--   - Sets a new CSRF token in a cookie
csrfProtection :: CSRFConfig -> Middleware
csrfProtection config app req respond = do
  let isSafe = isSafeMethod req
  let isExempt = isExemptPath config (rawPathInfo req)
  
  -- Always pass through if safe method or exempt path
  if isSafe || isExempt
    then do
      -- For safe methods, set a new CSRF token cookie if not present
      newToken <- generateCSRFToken
      let setCookieHeader =
            ( mk "Set-Cookie",
              BS.concat
                [ csrfCookieName config,
                  "=",
                  encode newToken,
                  "; Path=",
                  csrfCookiePath config,
                  if csrfSameSiteStrict config
                    then "; SameSite=Strict; HttpOnly; Secure"
                    else "; HttpOnly"
                ]
            )
      
      -- Modify response to add Set-Cookie header
      let modifyResp resp = resp { responseHeaders = setCookieHeader : responseHeaders resp }
      modifyResponse modifyResp app req respond
    
    -- State-changing request that's not exempt - validate CSRF
    else do
      if validateCSRF config req
        then app req respond
        else respond $ csrfFailureResponse

-- | Response for CSRF validation failure.
csrfFailureResponse :: Response
csrfFailureResponse =
  responseLBS
    status403
    [ (hContentType, "application/json")
    ]
    "{\"error\":\"CSRF validation failed\"}"
