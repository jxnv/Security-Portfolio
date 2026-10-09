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

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%ControlSet%' AND CommandLine ILIKE '%\\Control\\Lsa%') AND (CommandLine ILIKE '%Set-ItemProperty%' OR CommandLine ILIKE '%New-ItemProperty%' OR CommandLine ILIKE '% add %')) AND (((Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'reg.exe' OR OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%IsPplAutoEnabled%' OR CommandLine ILIKE '%RunAsPPL%' OR CommandLine ILIKE '%RunAsPPLBoot%')))
