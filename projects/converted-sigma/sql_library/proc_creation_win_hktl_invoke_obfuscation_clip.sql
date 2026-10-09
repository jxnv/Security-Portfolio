-- Title: Invoke-Obfuscation CLIP+ Launcher
-- ID: b222df08-0e07-11eb-adc1-0242ac120002
-- Status: test
-- Level: high
-- Author: Jonathan Cheong, oscd.community
-- Date: 2020-10-13
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated use of Clip.exe to execute PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%cmd%' AND CommandLine ILIKE '%&&%' AND CommandLine ILIKE '%clipboard]::%' AND CommandLine ILIKE '%-f%') AND (CommandLine ILIKE '%/c%' OR CommandLine ILIKE '%/r%'))
