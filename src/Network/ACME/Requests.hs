{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.Requests where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Status (statusCode)
import Data.Aeson (FromJSON, ToJSON, eitherDecode, encode, decode)
import Network.ACME.JWS (generatePrivateKey, signNew, signExisting, b64url, viewPublicKey)
import Network.HTTP.Types.Header (RequestHeaders, HeaderName, hContentType, hUserAgent, hAcceptLanguage, hLocation)
import Network.ACME.Types
import Data.ByteString.Char8 (unpack)
import Crypto.JOSE.JWS (JWK)

hReplayNonce :: HeaderName
hReplayNonce = "Replay-Nonce"

newTlsManager :: IO Manager
newTlsManager = newManager tlsManagerSettings


-- Ref. https://tools.ietf.org/html/draft-ietf-acme-acme-14#section-6.1
acmeHeaders :: RequestHeaders
acmeHeaders =
  [ (hContentType, "application/jose+json")
  , (hUserAgent, "http-client-acme")
  , (hAcceptLanguage, "en")
  ]

getDirectory :: Manager -> Url -> IO (Either String Directory)
getDirectory http url = do
  putStrLn "Getting directory..."
  request <- parseRequest url
  response <- httpLbs request http
  return $ eitherDecode $ responseBody response

getNonce :: Manager -> String -> IO (Either String Nonce)
getNonce manager url = do
  putStrLn "Getting nonce..."
  initial <- parseRequest url
  let request = initial { method = "HEAD" }
  response <- httpLbs request manager
  let mnonce = fmap (Nonce . unpack) <$> lookup hReplayNonce $ responseHeaders response
  return $ case mnonce of
    Nothing -> Left "getNonce: no nonce in header"
    Just nonce -> Right nonce

createAccount :: Manager -> Url -> JWK -> Nonce -> NewAccount -> IO (Either String (Url, Nonce))
createAccount manager url key nonce account = do
  putStrLn "Creating account..."
  payload <- signNew key nonce url account
  case payload of
    Left e -> return $ Left $ show e
    Right spayload -> do
      initial <- parseRequest url
      let request = initial { method = "POST"
                            , requestBody = RequestBodyLBS $ encode spayload
                            , requestHeaders = acmeHeaders
                            }
      response <- httpLbs request manager
      let mloc = lookup hLocation $ responseHeaders response
          mn   = lookup hReplayNonce $ responseHeaders response
          body :: Maybe AccountStatus
          body = decode $ responseBody response
      print body
      return $
        case (mloc, mn) of
          (Just loc, Just nonce) -> Right (unpack loc, Nonce $ unpack nonce)
          _                      -> Left "createAccount: something went wrong"

submitOrder :: Manager -> Url ->JWK -> Nonce -> Url -> NewOrder -> IO ()
submitOrder manager url key nonce accountUrl order = do
  payload <- signExisting key nonce url accountUrl order
  case payload of
    Left e -> print e
    Right spayload -> do
      initial <- parseRequest url
      let request = initial { method = "POST"
                            , requestBody = RequestBodyLBS $ encode spayload
                            , requestHeaders = acmeHeaders
                            }
      response <- httpLbs request manager
      print response
