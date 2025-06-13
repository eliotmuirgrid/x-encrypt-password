-- This module is a helpful utility if your script needs to use
-- a password that you don't want to appear in the lua code that
-- is saved in a repository.

-- The code uses AES encryption https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

-- http://help.interfaceware.com/v6/encrypt-password-in-file

ENCRYPTpassword = {}

local XmlSaveFragment=[[
<config password='' salt=''/>
]]

local function LoadFile(FileName)
   local F = io.open(FileName, "r")
   if not F then
      return nil
   end
   local C = F:read("*a")
   F:close()
   return C
end

local function SaveFile(FileName, Content)
   local F = io.open(FileName, "w")
   F:write(Content)  
   F:close()
end

function ENCRYPTpassword.load(T)
   local Config = T.config
   local Key = T.key
   local Data=LoadFile(Config)
   if not Data then
      return "No password file saved"
   end
   local X = xml.parse{data=Data}
   local Salt = X.config.salt:S()
   local TotalKey = filter.base64.enc(crypto.digest{data=Key .. Salt,algorithm='SHA512'}):sub(1,32)
   local Password = X.config.password:S()
   Password = filter.base64.dec(Password)
   Password = filter.aes.dec{data=Password, key=TotalKey}
   -- If we have a short password need to get rid
   -- of \0 padding.
   for i=#Password, 1, -1 do
      if Password:byte(i) ~= 0 then
         Password = Password:sub(1, i)
         break
      end
   end
   return Password
end

local Comment=[[
<!-- This config file was saved with the config.load -->
]]

local XmlSaveFragment=[[
<config password='' salt=''/>
]]

function ENCRYPTpassword.save(T)
   local Config   = T.config
   local Password = T.password
   local Key      = T.key
   local Salt     = util.generateGUID(128)
   local TotalKey = filter.base64.enc(crypto.digest{data=Key .. Salt,algorithm='SHA512'}):sub(1,32)
   local X        = xml.parse{data=XmlSaveFragment}
   
   local EncryptedPassword = filter.aes.enc{data=Password, key=TotalKey}
   EncryptedPassword = filter.base64.enc(EncryptedPassword)
   
   X.config.salt = Salt
   X.config.password = EncryptedPassword
   
   local Content = Comment..X:S()
   SaveFile(Config, Content)
end

help.map{dir='ENCRYPT', methods=ENCRYPTpassword}

return ENCRYPTpassword