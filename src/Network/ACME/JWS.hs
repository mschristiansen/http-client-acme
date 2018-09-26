{-# LANGUAGE OverloadedStrings #-}
module Network.ACME.JWS where

import Crypto.JOSE.JWS
import qualified Data.ByteString.Lazy as L
import Control.Monad.Trans.Except (runExceptT)
import Control.Lens (Lens', (&), set, view, review, preview, re)
import Crypto.JOSE.JWK (JWK, Digest, SHA256, base64url)
import Data.Aeson (ToJSON, encode, (.=))
import Crypto.JOSE.Types (Base64Octets(..))
import Data.Functor.Identity
import Network.ACME.Types (Nonce(..))
import Data.String (fromString)
import Data.Text.Strict.Lens (utf8)

-- | Generate a 4096 bit JSON Web Key (JWK).
generatePrivateKey :: IO JWK
generatePrivateKey = genJWK (ECGenParam P_256)

viewPublicKey :: JWK -> Maybe JWK
viewPublicKey = view asPublicKey

signNew :: ToJSON a => JWK -> Nonce -> String -> a -> IO (Either Error (JWS Identity Protection ACMEHeader))
signNew k (Nonce n) url payload = runExceptT $ signJWS (encode payload) (Identity (header, k))
  where
    -- Can be signed with either ES256 or EdDSA
    -- Each ES256 with RSA key
    header :: ACMEHeader Protection
    header = ACMEHeader (newJWSHeader (Protected, ES256)
      & set jwk (HeaderParam Protected <$> viewPublicKey k)) n url

signExisting :: ToJSON a => JWK -> Nonce -> String -> String -> a -> IO (Either Error (JWS Identity Protection ACMEHeader))
signExisting k (Nonce n) url accountUrl payload = runExceptT $ signJWS (encode payload) (Identity (header, k))
  where
    header :: ACMEHeader Protection
    header = ACMEHeader (newJWSHeader (Protected, ES256)
      & set kid (Just $ HeaderParam Protected accountUrl)) n url

b64url :: L.ByteString -> L.ByteString
b64url = review base64url

dec64url :: L.ByteString -> Maybe L.ByteString
dec64url = preview base64url


data ACMEHeader p = ACMEHeader
  { _acmeJwsHeader :: JWSHeader p
  , _acmeNonce     :: String
  , _acmeUrl       :: String
  }

acmeJwsHeader :: Lens' (ACMEHeader p) (JWSHeader p)
acmeJwsHeader f s@(ACMEHeader { _acmeJwsHeader = a}) =
  fmap (\a' -> s { _acmeJwsHeader = a'}) (f a)

acmeNonce :: Lens' (ACMEHeader p) String
acmeNonce f s@(ACMEHeader { _acmeNonce = a}) =
  fmap (\a' -> s { _acmeNonce = a'}) (f a)

acmeUrl :: Lens' (ACMEHeader p) String
acmeUrl f  s@(ACMEHeader { _acmeUrl = a}) =
  fmap (\a' -> s { _acmeUrl = a'}) (f a)

instance HasJWSHeader ACMEHeader where
  jwsHeader = acmeJwsHeader

instance HasParams ACMEHeader where
  parseParamsFor proxy hp hu =
    ACMEHeader <$> parseParamsFor proxy hp hu
               <*> headerRequiredProtected "nonce" hp hu
               <*> headerRequiredProtected "url" hp hu
  params h =
    (True, "url" .= view acmeUrl h) :
    (True, "nonce" .= view acmeNonce h) : params (view acmeJwsHeader h)
  extensions = const ["nonce", "url"]
