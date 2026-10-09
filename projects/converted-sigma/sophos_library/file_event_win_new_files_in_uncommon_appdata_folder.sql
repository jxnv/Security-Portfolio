-- Title: Suspicious File Creation In Uncommon AppData Folder
-- ID: d7b50671-d1ad-4871-aa60-5aa5b331fe04
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-05
-- Tags: attack.execution, attack.stealth
-- Description: Detects the creation of suspicious files and folders inside the user's AppData folder but not inside any of the common and well known directories (Local, Romaing, LocalLow). This method could be used as a method to bypass detection who exclude the AppData folder in fear of FPs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE 'C:\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\%' AND (TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.cpl' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.iso' OR TargetFilename ILIKE '%.lnk' OR TargetFilename ILIKE '%.msi' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.psm1' OR TargetFilename ILIKE '%.scr' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs')) AND NOT ((TargetFilename ILIKE 'C:\\Users\\%' AND (TargetFilename ILIKE '%\\AppData\\Local\\%' OR TargetFilename ILIKE '%\\AppData\\LocalLow\\%' OR TargetFilename ILIKE '%\\AppData\\Roaming\\%'))))
