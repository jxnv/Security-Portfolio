-- Title: PowerShell Execution With Potential Decryption Capabilities
-- ID: 434c08ba-8406-4d15-8b24-782cb071a691
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-30
-- Tags: attack.execution
-- Description: Detects PowerShell commands that decrypt an ".LNK" "file to drop the next stage of the malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Get-ChildItem %' OR CommandLine LIKE '%dir %' OR CommandLine LIKE '%gci %' OR CommandLine LIKE '%ls %')) AND ((CommandLine LIKE '%Get-Content %' OR CommandLine LIKE '%gc %' OR CommandLine LIKE '%cat %' OR CommandLine LIKE '%type %' OR CommandLine LIKE '%ReadAllBytes%')) AND (((CommandLine LIKE '% ^| %' AND CommandLine LIKE '%\\*.lnk%' AND CommandLine LIKE '%-Recurse%' AND CommandLine LIKE '%-Skip %')) OR ((CommandLine LIKE '% -ExpandProperty %' AND CommandLine LIKE '%\\*.lnk%' AND CommandLine LIKE '%WriteAllBytes%' AND CommandLine LIKE '% .length %'))) AND ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))
