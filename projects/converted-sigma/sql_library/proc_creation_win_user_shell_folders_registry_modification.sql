-- Title: User Shell Folders Registry Modification via CommandLine
-- ID: 8f3ab69a-aa22-4943-aa58-e0a52fdf6818
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-01-05
-- Tags: attack.persistence, attack.privilege-escalation, attack.defense-impairment, attack.t1547.001, attack.t1112
-- Description: Detects modifications to User Shell Folders registry values via reg.exe or PowerShell, which could indicate persistence attempts.
-- Attackers may modify User Shell Folders registry values to point to malicious executables or scripts that will be executed during startup.
-- This technique is often used to maintain persistence on a compromised system by ensuring that malicious payloads are executed automatically.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% add %' OR CommandLine ILIKE '%New-ItemProperty%' OR CommandLine ILIKE '%Set-ItemProperty%' OR CommandLine ILIKE '%si %')) AND ((CommandLine ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders%' OR CommandLine ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders%')) AND (CommandLine ILIKE '%Startup%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe')) OR ((OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'reg.exe'))))
