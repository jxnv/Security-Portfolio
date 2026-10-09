-- Title: User Discovery And Export Via Get-ADUser Cmdlet
-- ID: 1114e048-b69c-4f41-bc20-657245ae6e3f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.discovery, attack.t1033
-- Description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%Get-ADUser %' AND CommandLine ILIKE '% -Filter \\*%') AND (CommandLine ILIKE '% > %' OR CommandLine ILIKE '% | Select %' OR CommandLine ILIKE '%Out-File%' OR CommandLine ILIKE '%Set-Content%' OR CommandLine ILIKE '%Add-Content%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
