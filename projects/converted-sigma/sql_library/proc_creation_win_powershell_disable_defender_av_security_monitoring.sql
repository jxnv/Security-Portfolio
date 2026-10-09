-- Title: Disable Windows Defender AV Security Monitoring
-- ID: a7ee1722-c3c5-aeff-3212-c777e4733217
-- Status: test
-- Level: high
-- Author: ok @securonix invrep-de, oscd.community, frack113
-- Date: 2020-10-12
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attackers attempting to disable Windows Defender using Powershell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%-DisableBehaviorMonitoring $true%' OR CommandLine ILIKE '%-DisableRuntimeMonitoring $true%'))) OR (((Image ILIKE '%\\sc.exe') OR (OriginalFileName = 'sc.exe')) AND (((CommandLine ILIKE '%delete%' AND CommandLine ILIKE '%WinDefend%')) OR ((CommandLine ILIKE '%config%' AND CommandLine ILIKE '%WinDefend%' AND CommandLine ILIKE '%start=disabled%')) OR ((CommandLine ILIKE '%stop%' AND CommandLine ILIKE '%WinDefend%')))))
