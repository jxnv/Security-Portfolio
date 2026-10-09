-- Title: Potential Process Injection Via Msra.EXE
-- ID: 744a188b-0415-4792-896f-11ddb0588dbc
-- Status: test
-- Level: high
-- Author: Alexander McDonald
-- Date: 2022-06-24
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055
-- Description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\msra.exe" AND ParentCommandLine="*msra.exe" AND (Image="*\\arp.exe" OR Image="*\\cmd.exe" OR Image="*\\net.exe" OR Image="*\\netstat.exe" OR Image="*\\nslookup.exe" OR Image="*\\route.exe" OR Image="*\\schtasks.exe" OR Image="*\\whoami.exe"))
