-- Title: LSA PPL Protection Setting Modification via CommandLine
-- ID: 8c0eca51-0f88-4db2-9183-fdfb10c703f9
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2022-03-22
-- Tags: attack.defense-impairment, attack.t1689
-- Description: Detects modification of LSA PPL protection settings via CommandLine.
-- It may indicate an attempt to disable protection and enable credential dumping tools to access LSASS process memory.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%ControlSet%' AND CommandLine LIKE '%\\Control\\Lsa%') AND (CommandLine LIKE '%Set-ItemProperty%' OR CommandLine LIKE '%New-ItemProperty%' OR CommandLine LIKE '% add %')) AND (((Image="*\\reg.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'reg.exe' OR OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '%IsPplAutoEnabled%' OR CommandLine LIKE '%RunAsPPL%' OR CommandLine LIKE '%RunAsPPLBoot%')))
