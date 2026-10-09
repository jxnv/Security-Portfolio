-- Title: Potentially Suspicious Child Process Of WinRAR.EXE
-- ID: 146aace8-9bd6-42ba-be7a-0070d8027b76
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-31
-- Tags: attack.execution, attack.t1203
-- Description: Detects potentially suspicious child processes of WinRAR.exe.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'cscript.exe' OR OriginalFileName = 'mshta.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'regsvr32.exe' OR OriginalFileName = 'RUNDLL32.EXE' OR OriginalFileName = 'wscript.exe'))) AND (ParentImage ILIKE '%\\WinRAR.exe'))
