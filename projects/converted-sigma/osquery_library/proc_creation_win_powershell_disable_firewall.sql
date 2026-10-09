-- Title: Windows Firewall Disabled via PowerShell
-- ID: 12f6b752-042d-483e-bf9c-915a6d06ad75
-- Status: test
-- Level: medium
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-14
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attempts to disable the Windows Firewall using PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Set-NetFirewallProfile %' AND CommandLine LIKE '% -Enabled %' AND CommandLine LIKE '% False%')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\powershell_ise.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '% -All %' OR CommandLine LIKE '%Public%' OR CommandLine LIKE '%Domain%' OR CommandLine LIKE '%Private%')))
