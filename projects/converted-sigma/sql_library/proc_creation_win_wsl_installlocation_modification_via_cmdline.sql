-- Title: Suspicious WSL InstallLocation Registry Key Modification Via CommandLine
-- ID: f9f62824-de4e-40ca-afe7-8358f76a876d
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-05-05
-- Tags: attack.stealth, attack.defense-impairment, attack.persistence, attack.t1112, attack.t1218
-- Description: Detects the use of reg.exe or PowerShell to modify the WSL InstallLocation registry key via command-line arguments.
-- Legitimate modifications to this key are performed exclusively by the Windows Installer (msiexec.exe) during WSL package installation or update.
-- Manual use of reg.exe or PowerShell to set this value strongly indicates an attempt to redirect WSL execution to a malicious binary.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% add %' OR CommandLine ILIKE '%New-ItemProperty%' OR CommandLine ILIKE '%Set-ItemProperty%' OR CommandLine ILIKE '%sp %')) AND ((CommandLine ILIKE '%\\Lxss\\MSI%' OR CommandLine ILIKE '%/Lxss/MSI%')) AND (CommandLine ILIKE '%InstallLocation%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe')) OR ((OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'reg.exe'))))
