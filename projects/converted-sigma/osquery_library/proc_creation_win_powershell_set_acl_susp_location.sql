-- Title: PowerShell Set-Acl On Windows Folder
-- ID: 0944e002-e3f6-4eb5-bf69-3a3067b53d73
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.stealth
-- Description: Detects PowerShell scripts to set the ACL to a file in the Windows folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Set-Acl %' AND CommandLine LIKE '%-AclObject %')) AND (((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))) AND ((CommandLine LIKE '%-Path \"C:\\Windows%' OR CommandLine LIKE '%-Path 'C:\\Windows%' OR CommandLine LIKE '%-Path %windir%%' OR CommandLine LIKE '%-Path $env:windir%')) AND ((CommandLine LIKE '%FullControl%' OR CommandLine LIKE '%Allow%')))
