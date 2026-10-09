-- Title: Suspicious ArcSOC.exe Child Process
-- ID: 8e95e73e-ba02-4a87-b4d7-0929b8053038
-- Status: experimental
-- Level: high
-- Author: Micah Babinski
-- Date: 2025-11-25
-- Tags: attack.execution, attack.t1059, attack.t1203
-- Description: Detects script interpreters, command-line tools, and similar suspicious child processes of ArcSOC.exe.
-- ArcSOC.exe is the process name which hosts ArcGIS Server REST services. If an attacker compromises an ArcGIS
-- Server system and uploads a malicious Server Object Extension (SOE), they can send crafted requests to the corresponding
-- service endpoint and remotely execute code from the ArcSOC.exe process.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\ArcSOC.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe')) AND NOT ((Image ILIKE '%\\cmd.exe' AND CommandLine = 'cmd.exe /c \"ver\"')))
