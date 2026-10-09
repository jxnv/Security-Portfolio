-- Title: Execute Code with Pester.bat
-- ID: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-08
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1216
-- Description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND (CommandLine ILIKE '%Pester%' AND CommandLine ILIKE '%Get-Help%')) OR ((Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '%pester%' AND CommandLine ILIKE '%;%')) AND ((CommandLine ILIKE '%help%' OR CommandLine ILIKE '%\\?%'))))
