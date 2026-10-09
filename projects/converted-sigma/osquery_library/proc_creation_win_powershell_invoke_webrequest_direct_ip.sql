-- Title: Suspicious Invoke-WebRequest Execution With DirectIP
-- ID: 1edff897-9146-48d2-9066-52e8d8f80a2f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-21
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%curl %' OR CommandLine LIKE '%Invoke-RestMethod%' OR CommandLine LIKE '%Invoke-WebRequest%' OR CommandLine LIKE '% irm %' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%wget %')) AND (((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'powershell_ise.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '%://1%' OR CommandLine LIKE '%://2%' OR CommandLine LIKE '%://3%' OR CommandLine LIKE '%://4%' OR CommandLine LIKE '%://5%' OR CommandLine LIKE '%://6%' OR CommandLine LIKE '%://7%' OR CommandLine LIKE '%://8%' OR CommandLine LIKE '%://9%')))
