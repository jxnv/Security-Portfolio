-- Title: PowerShell Execution With Potential Decryption Capabilities
-- ID: 434c08ba-8406-4d15-8b24-782cb071a691
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-30
-- Tags: attack.execution
-- Description: Detects PowerShell commands that decrypt an ".LNK" "file to drop the next stage of the malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Get-ChildItem %' OR CommandLine ILIKE '%dir %' OR CommandLine ILIKE '%gci %' OR CommandLine ILIKE '%ls %')) AND ((CommandLine ILIKE '%Get-Content %' OR CommandLine ILIKE '%gc %' OR CommandLine ILIKE '%cat %' OR CommandLine ILIKE '%type %' OR CommandLine ILIKE '%ReadAllBytes%')) AND (((CommandLine ILIKE '% ^| %' AND CommandLine ILIKE '%\\*.lnk%' AND CommandLine ILIKE '%-Recurse%' AND CommandLine ILIKE '%-Skip %')) OR ((CommandLine ILIKE '% -ExpandProperty %' AND CommandLine ILIKE '%\\*.lnk%' AND CommandLine ILIKE '%WriteAllBytes%' AND CommandLine ILIKE '% .length %'))) AND ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND (OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))
