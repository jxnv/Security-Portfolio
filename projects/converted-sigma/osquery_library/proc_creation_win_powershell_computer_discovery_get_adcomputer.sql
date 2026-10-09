-- Title: Computer Discovery And Export Via Get-ADComputer Cmdlet
-- ID: 435e10e4-992a-4281-96f3-38b11106adde
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-11-10
-- Tags: attack.discovery, attack.t1033
-- Description: Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Get-ADComputer %' AND CommandLine LIKE '% -Filter \\*%') AND (CommandLine LIKE '% > %' OR CommandLine LIKE '% | Select %' OR CommandLine LIKE '%Out-File%' OR CommandLine LIKE '%Set-Content%' OR CommandLine LIKE '%Add-Content%')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
