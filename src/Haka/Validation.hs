{-# LANGUAGE OverloadedStrings #-}

module Haka.Validation
  ( validateUsername,
    validatePassword,
    validateProjectName,
    validateTokenName,
    validateTokenDescription,
    ValidationError (..),
    validateHeartbeatPayload,
  )
where

import qualified Data.Text as T
import Haka.Types (HeartbeatPayload (..), EntityType (..))

-- | Validation error type.
data ValidationError
  = UsernameTooShort
  | UsernameTooLong
  | UsernameInvalidChars
  | PasswordTooShort
  | PasswordTooLong
  | ProjectNameTooLong
  | ProjectNameInvalidChars
  | TokenNameTooLong
  | TokenDescriptionTooLong
  | HeartbeatEntityTooLong
  | HeartbeatProjectTooLong
  | HeartbeatBranchTooLong
  | HeartbeatLanguageTooLong
  deriving (Eq, Show)

-- | Maximum lengths for various fields.
maxUsernameLength :: Int
maxUsernameLength = 50

minUsernameLength :: Int
minUsernameLength = 3

maxPasswordLength :: Int
maxPasswordLength = 128

minPasswordLength :: Int
minPasswordLength = 8

maxProjectNameLength :: Int
maxProjectNameLength = 255

maxTokenNameLength :: Int
maxTokenNameLength = 100

maxTokenDescriptionLength :: Int
maxTokenDescriptionLength = 500

maxEntityLength :: Int
maxEntityLength = 1024

-- | Allowed characters in usernames.
-- Alphanumeric, underscore, hyphen, dot, and at sign.
usernameAllowedChars :: T.Text
usernameAllowedChars = T.pack "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.@"

-- | Allowed characters in project names.
-- More permissive than usernames to allow various naming conventions.
projectAllowedChars :: T.Text
projectAllowedChars = T.pack "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./ \t\n"

-- | Validate a username.
validateUsername :: Text -> Either ValidationError Text
validateUsername username
  | T.length username < minUsernameLength = Left UsernameTooShort
  | T.length username > maxUsernameLength = Left UsernameTooLong
  | T.any (\[email protected] -> c `T.notElem` usernameAllowedChars) username = Left UsernameInvalidChars
  | otherwise = Right username

-- | Validate a password.
validatePassword :: Text -> Either ValidationError Text
validatePassword password
  | T.length password < minPasswordLength = Left PasswordTooShort
  | T.length password > maxPasswordLength = Left PasswordTooLong
  | otherwise = Right password

-- | Validate a project name.
validateProjectName :: Maybe Text -> Either ValidationError (Maybe Text)
validateProjectName Nothing = Right Nothing
validateProjectName (Just name)
  | T.length name > maxProjectNameLength = Left ProjectNameTooLong
  | T.any (\[email protected] -> c `T.notElem` projectAllowedChars) name = Left ProjectNameInvalidChars
  | otherwise = Right (Just name)

-- | Validate a token name.
validateTokenName :: Maybe Text -> Either ValidationError (Maybe Text)
validateTokenName Nothing = Right Nothing
validateTokenName (Just name)
  | T.length name > maxTokenNameLength = Left TokenNameTooLong
  | otherwise = Right (Just name)

-- | Validate a token description.
validateTokenDescription :: Maybe Text -> Either ValidationError (Maybe Text)
validateTokenDescription Nothing = Right Nothing
validateTokenDescription (Just desc)
  | T.length desc > maxTokenDescriptionLength = Left TokenDescriptionTooLong
  | otherwise = Right (Just desc)

-- | Validate a heartbeat payload.
validateHeartbeatPayload :: HeartbeatPayload -> Either ValidationError HeartbeatPayload
validateHeartbeatPayload payload = do
  validatedEntity <- validateEntity (entity payload)
  validatedProject <- validateProjectName (project payload)
  validatedBranch <- validateBranch (branch payload)
  validatedLanguage <- validateLanguage (language payload)
  pure $ payload
    { entity = validatedEntity,
      project = validatedProject,
      branch = validatedBranch,
      language = validatedLanguage
    }
  where
    validateEntity :: Text -> Either ValidationError Text
    validateEntity e
      | T.length e > maxEntityLength = Left HeartbeatEntityTooLong
      | otherwise = Right e

    validateBranch :: Maybe Text -> Either ValidationError (Maybe Text)
    validateBranch Nothing = Right Nothing
    validateBranch (Just b)
      | T.length b > maxEntityLength = Left HeartbeatBranchTooLong
      | otherwise = Right (Just b)

    validateLanguage :: Maybe Text -> Either ValidationError (Maybe Text)
    validateLanguage Nothing = Right Nothing
    validateLanguage (Just l)
      | T.length l > 50 = Left HeartbeatLanguageTooLong
      | otherwise = Right (Just l)

-- | Convert validation error to a user-friendly message.
validationErrorToMessage :: ValidationError -> Text
validationErrorToMessage UsernameTooShort = "Username must be at least " <> T.pack (show minUsernameLength) <> " characters"
validationErrorToMessage UsernameTooLong = "Username must be at most " <> T.pack (show maxUsernameLength) <> " characters"
validationErrorToMessage UsernameInvalidChars = "Username contains invalid characters. Allowed: alphanumeric, _, -, ., @"
validationErrorToMessage PasswordTooShort = "Password must be at least " <> T.pack (show minPasswordLength) <> " characters"
validationErrorToMessage PasswordTooLong = "Password must be at most " <> T.pack (show maxPasswordLength) <> " characters"
validationErrorToMessage ProjectNameTooLong = "Project name must be at most " <> T.pack (show maxProjectNameLength) <> " characters"
validationErrorToMessage ProjectNameInvalidChars = "Project name contains invalid characters"
validationErrorToMessage TokenNameTooLong = "Token name must be at most " <> T.pack (show maxTokenNameLength) <> " characters"
validationErrorToMessage TokenDescriptionTooLong = "Token description must be at most " <> T.pack (show maxTokenDescriptionLength) <> " characters"
validationErrorToMessage HeartbeatEntityTooLong = "Entity path is too long"
validationErrorToMessage HeartbeatProjectTooLong = "Project name is too long"
validationErrorToMessage HeartbeatBranchTooLong = "Branch name is too long"
validationErrorToMessage HeartbeatLanguageTooLong = "Language name is too long"
