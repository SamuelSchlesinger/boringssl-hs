-- | PEM format encoding and decoding.
--
-- Provides pure Haskell PEM encoding/decoding using the existing
-- Base64 module. No additional FFI bindings needed.
module Crypto.BoringSSL.PEM
  ( pemEncode
  , pemDecode
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

import qualified Crypto.BoringSSL.Base64 as Base64

-- | Encode binary data in PEM format with the given type label.
--
-- @pemEncode "CERTIFICATE" derBytes@ produces:
--
-- > -----BEGIN CERTIFICATE-----
-- > <base64 data with line breaks every 64 characters>
-- > -----END CERTIFICATE-----
pemEncode :: String -> ByteString -> ByteString
pemEncode label derBytes =
  let b64 = Base64.encode derBytes
      header = BS8.pack ("-----BEGIN " ++ label ++ "-----\n")
      footer = BS8.pack ("\n-----END " ++ label ++ "-----\n")
      -- Insert line breaks every 64 characters
      wrapped = wrapLines 64 b64
  in BS.concat [header, wrapped, footer]

-- | Decode a PEM-encoded ByteString.
-- Returns @Just (label, derBytes)@ on success, or @Nothing@ if the
-- PEM format is invalid.
--
-- @pemDecode pem@ parses the PEM headers and base64-decodes the body.
pemDecode :: ByteString -> Maybe (String, ByteString)
pemDecode pem =
  let ls = BS8.lines (stripCR pem)
  in case ls of
    [] -> Nothing
    (hdr : rest) -> do
      label <- parseHeader hdr
      let (bodyLines, trailerLines) = break (isFooter label) rest
          body = BS.concat bodyLines
      case trailerLines of
        [] -> Nothing  -- No footer found
        _  -> case Base64.decode body of
                Right decoded -> Just (label, decoded)
                Left _        -> Nothing

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

-- | Strip carriage return characters for cross-platform compatibility.
stripCR :: ByteString -> ByteString
stripCR = BS.filter (/= 0x0D)
