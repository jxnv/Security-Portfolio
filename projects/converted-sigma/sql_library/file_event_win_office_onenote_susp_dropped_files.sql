-- Title: Suspicious File Created Via OneNote Application
-- ID: fcc6d700-68d9-4241-9a1a-06874d621b06
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-09
-- Tags: attack.stealth
-- Description: Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\onenote.exe' OR Image ILIKE '%\\onenotem.exe' OR Image ILIKE '%\\onenoteim.exe') AND TargetFilename ILIKE '%\\AppData\\Local\\Temp\\OneNote\\%' AND (TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.chm' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.htm' OR TargetFilename ILIKE '%.html' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.lnk' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.wsf'))
