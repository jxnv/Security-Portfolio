// Title: User Discovery And Export Via Get-ADUser Cmdlet
// ID: 1114e048-b69c-4f41-bc20-657245ae6e3f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.discovery, attack.t1033
// Description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "Get-ADUser " AND CommandLine contains " -Filter \\*") AND (CommandLine contains " > " OR CommandLine contains " | Select " OR CommandLine contains "Out-File" OR CommandLine contains "Set-Content" OR CommandLine contains "Add-Content")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll"))))
