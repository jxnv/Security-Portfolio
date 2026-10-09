-- Title: PowerShell Script Run in AppData
-- ID: ac175779-025a-4f12-98b0-acdaeb77ea85
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2019-01-09
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%powershell.exe%' OR CommandLine LIKE '%\\powershell%' OR CommandLine LIKE '%\\pwsh%' OR CommandLine LIKE '%pwsh.exe%')) AND ((CommandLine LIKE '%/c %' AND CommandLine LIKE '%\\AppData\\%') AND (CommandLine LIKE '%Local\\%' OR CommandLine LIKE '%Roaming\\%')))
