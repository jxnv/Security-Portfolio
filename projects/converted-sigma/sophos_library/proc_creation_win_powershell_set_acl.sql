-- Title: PowerShell Script Change Permission Via Set-Acl
-- ID: bdeb2cff-af74-4094-8426-724dc937f20a
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.stealth
-- Description: Detects PowerShell execution to set the ACL of a file or a folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%Set-Acl %' AND CommandLine ILIKE '%-AclObject %' AND CommandLine ILIKE '%-Path %')) AND (((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe'))))
