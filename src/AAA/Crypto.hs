-- | A small module providing necessary cryptographic functions
-- hiding the primitives used
module AAA.Crypto ( hash, salt, saltBinary ) where

import qualified Crypto.Hash.SHA256     as SHA256
import           Data.Binary            (Binary (), encode)
import           Data.ByteString        (ByteString (), append)
import qualified Data.ByteString.Base64 as B64

import           AAA.Types

-- | Gets something serializable and gives back hash of it.
hash :: (Binary t) => t -> Hash
hash = B64.encode . SHA256.hashlazy . encode

-- | Gets a hash, and a salt; and give back rehashed version with salt.
-- TODO: use this paper http://okmij.org/ftp/Haskell/tr-15-04.pdf
-- to get implicitly configured Salt.
-- This approach will both ensure that there isn't a ton of explicitly
-- passed params, and — more importantly — that for every use of AAA
-- Salt is globally the same.
salt :: Hash -> Salt -> Salted
salt x (Salt y) = (Salted . hash) $ append x y

-- | Gets something serializable and gives back its salted hash of its hash.
saltBinary :: (Binary t) => t -> Salt -> Salted
saltBinary x (Salt y) = (Salted . hash) $ append (hash x) y
