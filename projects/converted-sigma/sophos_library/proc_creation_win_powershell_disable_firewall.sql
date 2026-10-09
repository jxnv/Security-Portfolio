-- Title: Windows Firewall Disabled via PowerShell
-- ID: 12f6b752-042d-483e-bf9c-915a6d06ad75
-- Status: test
-- Level: medium
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-14
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects attempts to disable the Windows Firewall using PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%Set-NetFirewallProfile %' AND CommandLine ILIKE '% -Enabled %' AND CommandLine ILIKE '% False%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\powershell_ise.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '% -All %' OR CommandLine ILIKE '%Public%' OR CommandLine ILIKE '%Domain%' OR CommandLine ILIKE '%Private%')))
