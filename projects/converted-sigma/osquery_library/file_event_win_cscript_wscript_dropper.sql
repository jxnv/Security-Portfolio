-- Title: WScript or CScript Dropper - File
-- ID: 002bdb95-0cf1-46a6-9e08-d38c128a6127
-- Status: test
-- Level: high
-- Author: Tim Shelton
-- Date: 2022-01-10
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects a file ending in jse, vbe, js, vba, vbs, wsf, wsh written by cscript.exe or wscript.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Image="*\\wscript.exe" OR Image="*\\cscript.exe") AND (TargetFilename LIKE '%:\\Perflogs\\%' OR TargetFilename LIKE '%:\\ProgramData\\%' OR TargetFilename LIKE '%:\\Temp\\%' OR TargetFilename LIKE '%:\\Tmp\\%' OR TargetFilename LIKE '%:\\Users\\%' OR TargetFilename LIKE '%:\\Windows\\Temp\\%' OR TargetFilename LIKE '%\\AppData\\Local\\Temp%' OR TargetFilename LIKE '%\\AppData\\Roaming\\Temp%' OR TargetFilename LIKE '%\\Start Menu\\Programs\\Startup\\%' OR TargetFilename LIKE '%\\Temporary Internet%') AND (TargetFilename="*.js" OR TargetFilename="*.jse" OR TargetFilename="*.vba" OR TargetFilename="*.vbe" OR TargetFilename="*.vbs" OR TargetFilename="*.wsf" OR TargetFilename="*.wsh"))
