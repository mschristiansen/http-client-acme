{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Network.ACME.Types where

import GHC.Generics (Generic)
import Data.Aeson


type Url = String

newtype Nonce = Nonce String deriving Show


data Directory = Directory
  { newNonce   :: Url
  , newAccount :: Url
  , newOrder   :: Url
  , revokeCert :: Url
  , keyChange  :: Url
  , meta       :: DirectoryMeta
  } deriving (Generic, Show)

instance FromJSON Directory where
  parseJSON = genericParseJSON defaultOptions

data DirectoryMeta = DirectoryMeta
  { caaIdentities  :: [String]
  , termsOfService :: Url
  , website        :: Url
  } deriving (Generic, Show)

instance FromJSON DirectoryMeta where
  parseJSON = genericParseJSON defaultOptions

data NewAccount = NewAccount
  { contact              :: [String]
  , termsOfServiceAgreed :: Bool
  } deriving (Generic, Show)

instance ToJSON NewAccount where
  toEncoding = genericToEncoding defaultOptions

data AccountStatus = AccountStatus
  { status :: String
  , orders :: Maybe Url
  } deriving (Generic, Show)

instance FromJSON AccountStatus where
  parseJSON = genericParseJSON defaultOptions

data NewOrder = NewOrder
  { identifiers :: [OrderIdentifier]
  , notBefore   :: Maybe String
  , notAfter    :: Maybe String
  } deriving (Generic, Show)

instance ToJSON NewOrder where
  toEncoding = genericToEncoding defaultOptions

newtype OrderIdentifier = OrderIdentifier String deriving Show

instance ToJSON OrderIdentifier where
  toJSON (OrderIdentifier v) =
    object ["type" .= ("http" :: String), "value" .= v]
  toEncoding (OrderIdentifier v) =
    pairs ("type" .= ("http" :: String) <> "value" .= v)
