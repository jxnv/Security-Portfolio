-- Title: Potentially Suspicious Child Process Of VsCode
-- ID: 5a3164f2-b373-4152-93cf-090b13c12d27
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-26
-- Tags: attack.execution, attack.stealth, attack.t1218, attack.t1202
-- Description: Detects uncommon or suspicious child processes spawning from a VsCode "code.exe" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%\\code.exe') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\cmd.exe') AND (CommandLine ILIKE '%Invoke-Expressions%' OR CommandLine ILIKE '%IEX%' OR CommandLine ILIKE '%Invoke-Command%' OR CommandLine ILIKE '%ICM%' OR CommandLine ILIKE '%DownloadString%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%wscript%' OR CommandLine ILIKE '%cscript%')) OR ((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\wscript.exe')) OR ((Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%:\\Windows\\Temp\\%' OR Image ILIKE '%:\\Temp\\%'))))
