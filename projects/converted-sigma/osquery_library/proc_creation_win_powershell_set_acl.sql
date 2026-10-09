-- Title: PowerShell Script Change Permission Via Set-Acl
-- ID: bdeb2cff-af74-4094-8426-724dc937f20a
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.stealth
-- Description: Detects PowerShell execution to set the ACL of a file or a folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Set-Acl %' AND CommandLine LIKE '%-AclObject %' AND CommandLine LIKE '%-Path %')) AND (((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))))
