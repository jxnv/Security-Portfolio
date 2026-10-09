-- Title: WScript or CScript Dropper - File
-- ID: 002bdb95-0cf1-46a6-9e08-d38c128a6127
-- Status: test
-- Level: high
-- Author: Tim Shelton
-- Date: 2022-01-10
-- Tags: attack.execution, attack.t1059.005, attack.t1059.007
-- Description: Detects a file ending in jse, vbe, js, vba, vbs, wsf, wsh written by cscript.exe or wscript.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe') AND (TargetFilename ILIKE '%:\\Perflogs\\%' OR TargetFilename ILIKE '%:\\ProgramData\\%' OR TargetFilename ILIKE '%:\\Temp\\%' OR TargetFilename ILIKE '%:\\Tmp\\%' OR TargetFilename ILIKE '%:\\Users\\%' OR TargetFilename ILIKE '%:\\Windows\\Temp\\%' OR TargetFilename ILIKE '%\\AppData\\Local\\Temp%' OR TargetFilename ILIKE '%\\AppData\\Roaming\\Temp%' OR TargetFilename ILIKE '%\\Start Menu\\Programs\\Startup\\%' OR TargetFilename ILIKE '%\\Temporary Internet%') AND (TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.jse' OR TargetFilename ILIKE '%.vba' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.wsf' OR TargetFilename ILIKE '%.wsh'))
