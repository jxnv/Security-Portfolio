-- Title: PowerShell Set-Acl On Windows Folder
-- ID: 0944e002-e3f6-4eb5-bf69-3a3067b53d73
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.stealth
-- Description: Detects PowerShell scripts to set the ACL to a file in the Windows folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Set-Acl %' AND CommandLine ILIKE '%-AclObject %')) AND (((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe'))) AND ((CommandLine ILIKE '%-Path \"C:\\Windows%' OR CommandLine ILIKE '%-Path 'C:\\Windows%' OR CommandLine ILIKE '%-Path %windir%%' OR CommandLine ILIKE '%-Path $env:windir%')) AND ((CommandLine ILIKE '%FullControl%' OR CommandLine ILIKE '%Allow%')))
