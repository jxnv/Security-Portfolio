-- Title: Potentially Suspicious Child Processes Spawned by ConHost
-- ID: dfa03a09-8b92-4d83-8e74-f72839b1c407
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-05
-- Tags: attack.stealth, attack.t1202, attack.t1218
-- Description: Detects suspicious child processes related to Windows Shell utilities spawned by `conhost.exe`, which could indicate malicious activity using trusted system components.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((OriginalFileName = 'cmd.exe' OR OriginalFileName = 'cscript.exe' OR OriginalFileName = 'mshta.exe' OR OriginalFileName = 'powershell_ise.exe' OR OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'regsvr32.exe' OR OriginalFileName = 'wscript.exe'))) AND (ParentImage ILIKE '%\\conhost.exe'))
