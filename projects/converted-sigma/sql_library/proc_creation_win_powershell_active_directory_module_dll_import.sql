-- Title: Potential Active Directory Enumeration Using AD Module - ProcCreation
-- ID: 70bc5215-526f-4477-963c-a47a5c9ebd12
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2023-01-22
-- Tags: attack.reconnaissance, attack.discovery, attack.impact
-- Description: Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Import-Module %' OR CommandLine ILIKE '%ipmo %')) AND (CommandLine ILIKE '%Microsoft.ActiveDirectory.Management.dll%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
