-- Title: NTDS.DIT Creation By Uncommon Process
-- ID: 11b1ed55-154d-4e82-8ad7-83739298f720
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-11
-- Tags: attack.credential-access, attack.t1003.002, attack.t1003.003
-- Description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon process or a process located in a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\ntds.dit') AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\wsl.exe' OR Image ILIKE '%\\wt.exe')) OR ((Image ILIKE '%\\AppData\\%' OR Image ILIKE '%\\Temp\\%' OR Image ILIKE '%\\Public\\%' OR Image ILIKE '%\\PerfLogs\\%'))))
