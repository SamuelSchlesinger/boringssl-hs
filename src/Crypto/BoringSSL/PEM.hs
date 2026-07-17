-- | PEM format encoding and decoding.
--
-- Provides pure Haskell PEM encoding/decoding using the existing
-- Base64 module. No additional FFI bindings needed.
module Crypto.BoringSSL.PEM
  ( pemEncode
  , pemDecode
  , pemDecodeMany
  ) where

import Data.Char (isPrint)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

import Crypto.BoringSSL.Internal.Error
import qualified Crypto.BoringSSL.Base64 as Base64

-- | Encode binary data in PEM format with the given type label.
--
-- @pemEncode "CERTIFICATE" derBytes@ produces:
--
-- > -----BEGIN CERTIFICATE-----
-- > <base64 data with line breaks every 64 characters>
-- > -----END CERTIFICATE-----
--
-- The label is validated: it must be non-empty and contain only
-- printable characters other than @-@. Without this check a caller
-- passing attacker-influenced text could inject @-----BEGIN ...-----@
-- framing or newlines and forge extra PEM blocks.
pemEncode :: String -> ByteString -> Either CryptoError ByteString
pemEncode label derBytes
  | null label = Left (InvalidInput "pemEncode: label must not be empty")
  | any (\c -> c == '-' || not (isPrint c)) label =
      Left (InvalidInput "pemEncode: label must contain only printable characters and no '-'")
  | otherwise =
  case Base64.encode derBytes of
    Left err -> Left err
    Right b64 ->
      let header = BS8.pack ("-----BEGIN " ++ label ++ "-----\n")
          footer = BS8.pack ("\n-----END " ++ label ++ "-----\n")
          -- Insert line breaks every 64 characters
          wrapped = wrapLines 64 b64
      in Right (BS.concat [header, wrapped, footer])

-- | Decode a PEM-encoded ByteString.
-- Returns @Right (label, derBytes)@ on success, or @Left err@ if the
-- PEM format is invalid.
--
-- @pemDecode pem@ parses the PEM headers and base64-decodes the body.
pemDecode :: ByteString -> Either CryptoError (String, ByteString)
pemDecode pem =
  let ls = BS8.lines (stripCR pem)
  in case ls of
    [] -> Left (DecodeError "pemDecode: empty input")
    (hdr : rest) ->
      case parseHeader hdr of
        Nothing -> Left (DecodeError "pemDecode: invalid PEM header")
        Just label ->
          let (bodyLines, trailerLines) = break (isFooter label) rest
              body = BS.concat bodyLines
          in case trailerLines of
            [] -> Left (DecodeError "pemDecode: missing PEM footer")
            _  -> case Base64.decode body of
                    Right decoded -> Right (label, decoded)
                    Left err      -> Left err

-- | Parse a PEM header line like "-----BEGIN CERTIFICATE-----"
-- and return the label.
parseHeader :: ByteString -> Maybe String
parseHeader line =
  let prefix = BS8.pack "-----BEGIN "
      suffix = BS8.pack "-----"
  in if BS.isPrefixOf prefix line && BS.isSuffixOf suffix (BS8.dropWhile (== ' ') line)
     then let stripped = BS.drop (BS.length prefix) line
              labelBS = BS.take (BS.length stripped - BS.length suffix) stripped
          in if BS.null labelBS
             then Nothing
             else Just (BS8.unpack labelBS)
     else Nothing

-- | Check if a line is the PEM footer for a given label.
isFooter :: String -> ByteString -> Bool
isFooter label line =
  let expected = BS8.pack ("-----END " ++ label ++ "-----")
  in BS8.strip line == expected

-- | Insert newlines every @n@ characters in a ByteString.
wrapLines :: Int -> ByteString -> ByteString
wrapLines n bs
  | BS.null bs = BS.empty
  | otherwise  =
      let (chunk, rest) = BS.splitAt n bs
      in if BS.null rest
         then chunk
         else BS.concat [chunk, BS8.pack "\n", wrapLines n rest]

-- | Decode all PEM blocks from a ByteString.
-- Returns @Right [(label, derBytes)]@ on success.
-- Returns @Left@ if no blocks are found or if any block has
-- invalid base64 or a missing footer. Junk between blocks is skipped.
pemDecodeMany :: ByteString -> Either CryptoError [(String, ByteString)]
pemDecodeMany pem =
  let ls = BS8.lines (stripCR pem)
      blocks = decodeBlocks ls
  in case blocks of
    Left err -> Left err
    Right [] -> Left (DecodeError "pemDecodeMany: no PEM blocks found")
    Right xs -> Right xs
  where
    decodeBlocks :: [ByteString] -> Either CryptoError [(String, ByteString)]
    decodeBlocks [] = Right []
    decodeBlocks (l:rest) =
      case parseHeader l of
        Nothing -> decodeBlocks rest  -- skip junk lines
        Just label ->
          let (bodyLines, trailerAndRest) = break (isFooter label) rest
              body = BS.concat bodyLines
          in case trailerAndRest of
            [] -> Left (DecodeError ("pemDecodeMany: missing footer for " ++ label))
            (_:remaining) ->
              case Base64.decode body of
                Left err -> Left err
                Right decoded -> do
                  moreBlocks <- decodeBlocks remaining
                  Right ((label, decoded) : moreBlocks)

-- | Strip carriage return characters for cross-platform compatibility.
stripCR :: ByteString -> ByteString
stripCR = BS.filter (/= 0x0D)
