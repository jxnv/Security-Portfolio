-- Title: Suspicious Invoke-WebRequest Execution
-- ID: 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-02
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%curl %' OR CommandLine LIKE '%Invoke-WebRequest%' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%wget %')) AND ((CommandLine LIKE '% -ur%' OR CommandLine LIKE '% -o%')) AND (((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'powershell_ise.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '%\\AppData\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Temp\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%%AppData%%' OR CommandLine LIKE '%%Public%%' OR CommandLine LIKE '%%Temp%%' OR CommandLine LIKE '%%tmp%%' OR CommandLine LIKE '%:\\Windows\\%')))
