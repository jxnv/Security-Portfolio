-- Title: PowerShell Download Pattern
-- ID: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
-- Date: 2019-01-16
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a Powershell process that contains download commands in its command line string
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%new-object%' AND CommandLine LIKE '%net.webclient).%' AND CommandLine LIKE '%download%') AND (CommandLine LIKE '%string(%' OR CommandLine LIKE '%file(%')) AND (((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell_ISE.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
