module Haka.Middleware
  ( jsonResponse,
    securityHeaders,
    csrfProtection,
    CSRFConfig (..),
    defaultCSRFConfig,
  )
where

import Data.Aeson
import Data.ByteString.Builder
import Data.Text (isInfixOf)
import Network.HTTP.Types
import Network.Wai
import Network.Wai.Internal
import Haka.Middleware.CSRF

-- | Middleware to convert client errors in JSON
jsonResponse :: Application -> Application
jsonResponse = modifyResponse responseModifier

responseModifier :: Response -> Response
responseModifier r
  | responseStatus r == status400 && not (isCustomMessage r "Bad Request") =
    buildResponse status400 "BadRequest" (customErrorBody r "BadRequest")
  | responseStatus r == status405 =
    buildResponse status400 "MethodNotAllowed" "Ensure that the Content-Type header field is set correctly"
  | otherwise = r

-- | Security headers middleware.
-- Adds standard security headers to all responses.
securityHeaders :: Middleware
securityHeaders = addHeaders [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "1; mode=block"),
    ("Referrer-Policy", "same-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
    -- Content-Security-Policy - be careful with this as it may break the dashboard
    -- Start with a permissive policy and tighten as needed
    ("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' fonts.googleapis.com; img-src 'self' data: fonts.gstatic.com; font-src 'self' fonts.gstatic.com; connect-src 'self'")
  ]
  where
    addHeaders :: [(BS.ByteString, BS.ByteString)] -> Middleware
    addHeaders headers app req respond = do
      app req $ \resp -> do
        let existingHeaders = responseHeaders resp
        let newHeaders = headers ++ existingHeaders
        respond $ resp { responseHeaders = newHeaders }

-- | Re-export CSRF middleware
csrfProtection :: CSRFConfig -> Middleware
csrfProtection = Haka.Middleware.CSRF.csrfProtection

defaultCSRFConfig :: CSRFConfig
defaultCSRFConfig = Haka.Middleware.CSRF.defaultCSRFConfig

customErrorBody :: Response -> Text -> Text
customErrorBody (ResponseBuilder _ _ b) _ = decodeUtf8 $ toLazyByteString b
customErrorBody (ResponseRaw _ res) e = customErrorBody res e
customErrorBody _ e = e

isCustomMessage :: Response -> Text -> Bool
isCustomMessage r m = "{\"error\":" `isInfixOf` customErrorBody r m

buildResponse :: Status -> Text -> Text -> Response
buildResponse st err msg =
  responseBuilder
    st
    [("Content-Type", "application/json")]
    ( lazyByteString $
        encode $
          object
            [ "error" .= err,
              "message" .= msg
            ]
    )
