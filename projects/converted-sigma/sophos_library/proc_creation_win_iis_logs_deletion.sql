-- Title: IIS WebServer Log Deletion via CommandLine Utilities
-- ID: 0649be4a-aeb0-45b0-b89e-7f1668f6d9c0
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-09-02
-- Tags: attack.stealth, attack.t1070
-- Description: Detects attempts to delete Internet Information Services (IIS) log files via command line utilities, which is a common defense evasion technique used by attackers to cover their tracks.
-- Threat actors often abuse vulnerabilities in web applications hosted on IIS servers to gain initial access and later delete IIS logs to evade detection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%del %' OR CommandLine ILIKE '%erase %' OR CommandLine ILIKE '%rm %' OR CommandLine ILIKE '%remove-item %' OR CommandLine ILIKE '%rmdir %')) AND (CommandLine ILIKE '%\\inetpub\\logs\\%') AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'cmd.exe' OR OriginalFileName = 'powershell.exe' OR OriginalFileName = 'powershell_ise.exe' OR OriginalFileName = 'pwsh.dll'))))
