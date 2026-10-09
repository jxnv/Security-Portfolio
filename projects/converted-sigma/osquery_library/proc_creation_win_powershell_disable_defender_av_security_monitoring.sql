-- Title: Disable Windows Defender AV Security Monitoring
-- ID: a7ee1722-c3c5-aeff-3212-c777e4733217
-- Status: test
-- Level: high
-- Author: ok @securonix invrep-de, oscd.community, frack113
-- Date: 2020-10-12
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attackers attempting to disable Windows Defender using Powershell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '%-DisableBehaviorMonitoring $true%' OR CommandLine LIKE '%-DisableRuntimeMonitoring $true%'))) OR (((Image="*\\sc.exe") OR (OriginalFileName = 'sc.exe')) AND (((CommandLine LIKE '%delete%' AND CommandLine LIKE '%WinDefend%')) OR ((CommandLine LIKE '%config%' AND CommandLine LIKE '%WinDefend%' AND CommandLine LIKE '%start=disabled%')) OR ((CommandLine LIKE '%stop%' AND CommandLine LIKE '%WinDefend%')))))
