-- Title: Suspicious Invoke-WebRequest Execution With DirectIP
-- ID: 1edff897-9146-48d2-9066-52e8d8f80a2f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-21
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%curl %' OR CommandLine ILIKE '%Invoke-RestMethod%' OR CommandLine ILIKE '%Invoke-WebRequest%' OR CommandLine ILIKE '% irm %' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%wget %')) AND (((Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'powershell_ise.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%://1%' OR CommandLine ILIKE '%://2%' OR CommandLine ILIKE '%://3%' OR CommandLine ILIKE '%://4%' OR CommandLine ILIKE '%://5%' OR CommandLine ILIKE '%://6%' OR CommandLine ILIKE '%://7%' OR CommandLine ILIKE '%://8%' OR CommandLine ILIKE '%://9%')))
