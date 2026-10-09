-- Title: Renamed Powershell Under Powershell Channel
-- ID: 30a8cb77-8eb3-4cfb-8e79-ad457c5a4592
-- Status: test
-- Level: low
-- Author: Harish Segar, frack113
-- Date: 2020-06-29
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1036.003
-- Description: Detects a renamed Powershell execution, which is a common technique used to circumvent security controls and bypass detection logic that's dependent on process names and process paths.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Data ILIKE '%HostName=ConsoleHost%') AND NOT (((REGEXP_LIKE(Data, 'HostId=[a-zA-Z0-9-]{36}\s+EngineVersion=')) OR ((Data ILIKE '%HostApplication=powershell%' OR Data ILIKE '%HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR Data ILIKE '%HostApplication=C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%' OR Data ILIKE '%HostApplication=C:/Windows/System32/WindowsPowerShell/v1.0/powershell%' OR Data ILIKE '%HostApplication=C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell%' OR Data ILIKE '%HostApplication=C:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe%' OR Data ILIKE '%HostApplication=C:\\\\\\\\WINDOWS\\\\\\\\SysWOW64\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe%')))))
