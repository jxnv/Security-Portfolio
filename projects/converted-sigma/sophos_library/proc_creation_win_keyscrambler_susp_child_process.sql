-- Title: Potentially Suspicious Child Process of KeyScrambler.exe
-- ID: ca5583e9-8f80-46ac-ab91-7f314d13b984
-- Status: test
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel
-- Date: 2024-05-13
-- Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.stealth, attack.t1203, attack.t1574.001
-- Description: Detects potentially suspicious child processes of KeyScrambler.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'cscript.exe' OR OriginalFileName = 'mshta.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'regsvr32.exe' OR OriginalFileName = 'RUNDLL32.EXE' OR OriginalFileName = 'wscript.exe'))) AND (ParentImage ILIKE '%\\KeyScrambler.exe'))
