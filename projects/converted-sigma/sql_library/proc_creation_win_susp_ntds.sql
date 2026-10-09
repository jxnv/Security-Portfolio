-- Title: Suspicious Process Patterns NTDS.DIT Exfil
-- ID: 8bc64091-6875-4881-aaf9-7bd25b5dda08
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-11
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects suspicious process patterns used in NTDS.DIT exfiltration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%ac i ntds%' AND CommandLine ILIKE '%create full%')) OR ((CommandLine ILIKE '%/c copy %' AND CommandLine ILIKE '%\\windows\\ntds\\ntds.dit%')) OR ((CommandLine ILIKE '%activate instance ntds%' AND CommandLine ILIKE '%create full%')) OR ((CommandLine ILIKE '%powershell%' AND CommandLine ILIKE '%ntds.dit%')) OR (((Image ILIKE '%\\NTDSDump.exe' OR Image ILIKE '%\\NTDSDumpEx.exe')) OR ((CommandLine ILIKE '%ntds.dit%' AND CommandLine ILIKE '%system.hiv%')) OR (CommandLine ILIKE '%NTDSgrab.ps1%'))) OR ((((ParentImage ILIKE '%\\apache%' OR ParentImage ILIKE '%\\tomcat%' OR ParentImage ILIKE '%\\AppData\\%' OR ParentImage ILIKE '%\\Temp\\%' OR ParentImage ILIKE '%\\Public\\%' OR ParentImage ILIKE '%\\PerfLogs\\%')) OR ((Image ILIKE '%\\apache%' OR Image ILIKE '%\\tomcat%' OR Image ILIKE '%\\AppData\\%' OR Image ILIKE '%\\Temp\\%' OR Image ILIKE '%\\Public\\%' OR Image ILIKE '%\\PerfLogs\\%'))) AND (CommandLine ILIKE '%ntds.dit%')))
