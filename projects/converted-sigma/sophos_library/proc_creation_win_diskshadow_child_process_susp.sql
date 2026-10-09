-- Title: Potentially Suspicious Child Process Of DiskShadow.EXE
-- ID: 9f546b25-5f12-4c8d-8532-5893dcb1e4b8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-15
-- Tags: attack.stealth, attack.t1218
-- Description: Detects potentially suspicious child processes of "Diskshadow.exe". This could be an attempt to bypass parent/child relationship detection or application whitelisting rules.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\diskshadow.exe' AND (Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe'))
