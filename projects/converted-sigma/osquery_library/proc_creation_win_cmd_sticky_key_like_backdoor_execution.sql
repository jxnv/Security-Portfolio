-- Title: Sticky Key Like Backdoor Execution
-- ID: 2fdefcb3-dbda-401e-ae23-f0db027628bc
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community
-- Date: 2018-03-15
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.008, car.2014-11-003, car.2014-11-008
-- Description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\winlogon.exe" AND (Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe" OR Image="*\\wt.exe") AND (CommandLine LIKE '%sethc.exe%' OR CommandLine LIKE '%utilman.exe%' OR CommandLine LIKE '%osk.exe%' OR CommandLine LIKE '%Magnify.exe%' OR CommandLine LIKE '%Narrator.exe%' OR CommandLine LIKE '%DisplaySwitch.exe%'))
