-- Title: Execute Code with Pester.bat
-- ID: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-08
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1216
-- Description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%Pester%' AND CommandLine LIKE '%Get-Help%')) OR ((Image="*\\cmd.exe" AND (CommandLine LIKE '%pester%' AND CommandLine LIKE '%;%')) AND ((CommandLine LIKE '%help%' OR CommandLine LIKE '%\\?%'))))
