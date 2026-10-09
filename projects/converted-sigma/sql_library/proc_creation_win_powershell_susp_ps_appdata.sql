-- Title: PowerShell Script Run in AppData
-- ID: ac175779-025a-4f12-98b0-acdaeb77ea85
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2019-01-09
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%powershell.exe%' OR CommandLine ILIKE '%\\powershell%' OR CommandLine ILIKE '%\\pwsh%' OR CommandLine ILIKE '%pwsh.exe%')) AND ((CommandLine ILIKE '%/c %' AND CommandLine ILIKE '%\\AppData\\%') AND (CommandLine ILIKE '%Local\\%' OR CommandLine ILIKE '%Roaming\\%')))
