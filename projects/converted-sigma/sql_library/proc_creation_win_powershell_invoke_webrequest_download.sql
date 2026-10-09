-- Title: Suspicious Invoke-WebRequest Execution
-- ID: 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-02
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%curl %' OR CommandLine ILIKE '%Invoke-WebRequest%' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%wget %')) AND ((CommandLine ILIKE '% -ur%' OR CommandLine ILIKE '% -o%')) AND (((Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'powershell_ise.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%\\AppData\\%' OR CommandLine ILIKE '%\\Desktop\\%' OR CommandLine ILIKE '%\\Temp\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%%AppData%%' OR CommandLine ILIKE '%%Public%%' OR CommandLine ILIKE '%%Temp%%' OR CommandLine ILIKE '%%tmp%%' OR CommandLine ILIKE '%:\\Windows\\%')))
