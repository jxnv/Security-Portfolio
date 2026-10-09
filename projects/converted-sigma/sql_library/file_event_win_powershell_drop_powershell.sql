-- Title: PowerShell Script Dropped Via PowerShell.EXE
-- ID: 576426ad-0131-4001-ae01-be175da0c108
-- Status: test
-- Level: low
-- Author: frack113
-- Date: 2023-05-09
-- Tags: attack.persistence
-- Description: Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND TargetFilename ILIKE '%.ps1') AND NOT (((TargetFilename ILIKE 'C:\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\Local\\Temp\\%') OR (TargetFilename ILIKE '%__PSScriptPolicyTest_%') OR (TargetFilename ILIKE 'C:\\Windows\\Temp\\%'))))
