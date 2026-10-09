-- Title: Potentially Suspicious DMP/HDMP File Creation
-- ID: aba15bdd-657f-422a-bab3-ac2d2a0d6f1c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-07
-- Tags: attack.stealth
-- Description: Detects the creation of a file with the ".dmp"/".hdmp" extension by a shell or scripting application such as "cmd", "powershell", etc. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wscript.exe') AND (TargetFilename ILIKE '%.dmp' OR TargetFilename ILIKE '%.dump' OR TargetFilename ILIKE '%.hdmp'))
