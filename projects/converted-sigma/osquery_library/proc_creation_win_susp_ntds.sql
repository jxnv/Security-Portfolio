-- Title: Suspicious Process Patterns NTDS.DIT Exfil
-- ID: 8bc64091-6875-4881-aaf9-7bd25b5dda08
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-11
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects suspicious process patterns used in NTDS.DIT exfiltration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%ac i ntds%' AND CommandLine LIKE '%create full%')) OR ((CommandLine LIKE '%/c copy %' AND CommandLine LIKE '%\\windows\\ntds\\ntds.dit%')) OR ((CommandLine LIKE '%activate instance ntds%' AND CommandLine LIKE '%create full%')) OR ((CommandLine LIKE '%powershell%' AND CommandLine LIKE '%ntds.dit%')) OR (((Image="*\\NTDSDump.exe" OR Image="*\\NTDSDumpEx.exe")) OR ((CommandLine LIKE '%ntds.dit%' AND CommandLine LIKE '%system.hiv%')) OR (CommandLine LIKE '%NTDSgrab.ps1%'))) OR ((((ParentImage LIKE '%\\apache%' OR ParentImage LIKE '%\\tomcat%' OR ParentImage LIKE '%\\AppData\\%' OR ParentImage LIKE '%\\Temp\\%' OR ParentImage LIKE '%\\Public\\%' OR ParentImage LIKE '%\\PerfLogs\\%')) OR ((Image LIKE '%\\apache%' OR Image LIKE '%\\tomcat%' OR Image LIKE '%\\AppData\\%' OR Image LIKE '%\\Temp\\%' OR Image LIKE '%\\Public\\%' OR Image LIKE '%\\PerfLogs\\%'))) AND (CommandLine LIKE '%ntds.dit%')))
