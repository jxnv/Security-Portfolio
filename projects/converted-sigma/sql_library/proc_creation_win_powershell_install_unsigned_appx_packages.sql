-- Title: Unsigned AppX Installation Attempt Using Add-AppxPackage
-- ID: 37651c2a-42cd-4a69-ae0d-22a4349aa04a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-31
-- Tags: attack.persistence, attack.stealth
-- Description: Detects usage of the "Add-AppxPackage" or it's alias "Add-AppPackage" to install unsigned AppX packages
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Add-AppPackage %' OR CommandLine ILIKE '%Add-AppxPackage %')) AND (CommandLine ILIKE '% -AllowUnsigned%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
